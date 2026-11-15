// SPDX-License-Identifier: MPL-2.0
// Independent CRT-based dataflow witness using an isolated initializer.
// The number-theory mechanism is described by Dalla Preda and Ianni,
// https://doi.org/10.1007/s11416-023-00489-8 . No third-party pass code is
// used.
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#if defined(FILEVEIL_STANDALONE_DRIVER)
#include "llvm/IR/LLVMContext.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/SourceMgr.h"
#else
#include "llvm/Passes/PassBuilder.h"
#if __has_include("llvm/Plugins/PassPlugin.h")
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif
#endif
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

using namespace llvm;

namespace {
constexpr StringLiteral Marker = "fileveil.software.ir.v1";
constexpr StringLiteral CarrierName = "__fileveil_swm_carrier_v1";
constexpr StringLiteral DescriptorName = "__fileveil_swm_descriptor_v1";
constexpr StringLiteral SeedName = "__fileveil_swm_seed_v1";
constexpr StringLiteral ValuesName = "__fileveil_swm_values_v1";
constexpr StringLiteral ScratchName = "__fileveil_swm_scratch_v1";
constexpr StringLiteral ConstructorName = "__fileveil_swm_init_v1";
constexpr StringLiteral ProbeName = "fileveil_swm_probe_v1";
constexpr size_t MaxPacketBytes = 32768;
constexpr std::array<uint32_t, 9> Primes = {251, 241, 239, 233, 229,
                                            227, 223, 211, 199};
constexpr std::array<StringLiteral, 7> OwnedNames = {
    CarrierName, DescriptorName,  SeedName, ValuesName,
    ScratchName, ConstructorName, ProbeName};

[[noreturn]] void reject(const Twine &Message) {
  errs() << "FileVeil software watermark: " << Message << '\n';
  std::exit(2);
}

std::string hex(ArrayRef<uint8_t> Bytes) {
  static constexpr char Digits[] = "0123456789abcdef";
  std::string Result;
  Result.reserve(Bytes.size() * 2);
  for (uint8_t Byte : Bytes) {
    Result.push_back(Digits[Byte >> 4]);
    Result.push_back(Digits[Byte & 15]);
  }
  return Result;
}

std::vector<uint8_t> unhex(StringRef Text) {
  if ((Text.size() & 1) || Text.size() > MaxPacketBytes * 2)
    reject("hexadecimal packet has an invalid length");
  std::vector<uint8_t> Bytes;
  Bytes.reserve(Text.size() / 2);
  auto Digit = [](char Value) -> uint8_t {
    if (Value >= '0' && Value <= '9')
      return Value - '0';
    if (Value >= 'a' && Value <= 'f')
      return Value - 'a' + 10;
    if (Value >= 'A' && Value <= 'F')
      return Value - 'A' + 10;
    reject("packet contains invalid hexadecimal characters");
  };
  for (size_t Index = 0; Index < Text.size(); Index += 2)
    Bytes.push_back((Digit(Text[Index]) << 4) | Digit(Text[Index + 1]));
  return Bytes;
}

uint64_t word(StringRef Text) {
  if (Text.size() != 16)
    reject("witness and challenge require sixteen hexadecimal digits");
  uint64_t Value = 0;
  if (Text.getAsInteger(16, Value))
    reject("invalid witness or challenge");
  return Value;
}

void append32(std::vector<uint8_t> &Bytes, uint32_t Value) {
  for (unsigned Shift = 0; Shift < 32; Shift += 8)
    Bytes.push_back(Value >> Shift);
}
void append64(std::vector<uint8_t> &Bytes, uint64_t Value) {
  for (unsigned Shift = 0; Shift < 64; Shift += 8)
    Bytes.push_back(Value >> Shift);
}
uint32_t read32(ArrayRef<uint8_t> Bytes, size_t Offset) {
  uint32_t Value = 0;
  for (unsigned Index = 0; Index < 4; ++Index)
    Value |= uint32_t(Bytes[Offset + Index]) << (Index * 8);
  return Value;
}
uint64_t read64(ArrayRef<uint8_t> Bytes, size_t Offset) {
  uint64_t Value = 0;
  for (unsigned Index = 0; Index < 8; ++Index)
    Value |= uint64_t(Bytes[Offset + Index]) << (Index * 8);
  return Value;
}

uint64_t splitmix(uint64_t &State) {
  uint64_t Value = (State += UINT64_C(0x9e3779b97f4a7c15));
  Value = (Value ^ (Value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  Value = (Value ^ (Value >> 27)) * UINT64_C(0x94d049bb133111eb);
  return Value ^ (Value >> 31);
}

std::string moduleDigest(Module &M) {
  // The identifier is an input-path comment. It changes when opt reads a copy.
  const std::string Identifier = M.getModuleIdentifier();
  M.setModuleIdentifier("");
  std::string Printed;
  raw_string_ostream Stream(Printed);
  M.print(Stream, nullptr);
  Stream.flush();
  M.setModuleIdentifier(Identifier);
  return hex(SHA256::hash(ArrayRef<uint8_t>(
      reinterpret_cast<const uint8_t *>(Printed.data()), Printed.size())));
}

struct Packet {
  std::vector<uint8_t> Bytes;
  uint64_t Witness;
  uint64_t Challenge;
};
Packet readPacket() {
  const char *Path = std::getenv("FILEVEIL_SOFTWARE_PACKET");
  if (!Path || !*Path)
    reject("FILEVEIL_SOFTWARE_PACKET must identify a public pass packet");
  sys::fs::file_status Status;
  if (sys::fs::status(Path, Status) || !sys::fs::is_regular_file(Status) ||
      Status.getSize() > 128 * 1024)
    reject("pass packet must be a bounded regular file");
  auto Buffer = MemoryBuffer::getFile(Path);
  if (!Buffer)
    reject("could not read the public pass packet");
  if ((*Buffer)->getBufferSize() > 128 * 1024)
    reject("pass packet changed beyond the size limit");
  auto Parsed = json::parse((*Buffer)->getBuffer());
  if (!Parsed) {
    consumeError(Parsed.takeError());
    reject("invalid pass packet JSON");
  }
  auto *Object = Parsed->getAsObject();
  if (!Object ||
      Object->getString("schema") != "fileveil.software.pass_packet.v1")
    reject("unknown pass packet schema");
  auto Payload = Object->getString("packet_hex");
  auto Witness = Object->getString("witness_hex");
  if (!Payload || Payload->empty() || !Witness)
    reject("packet_hex and witness_hex are required");
  auto Challenge = Object->getString("challenge_hex");
  return Packet{unhex(*Payload), word(*Witness),
                Challenge ? word(*Challenge) : 0};
}

std::vector<uint8_t> carrier(const Packet &Input) {
  std::vector<uint8_t> Bytes = {'F', 'V', 'S', 'W', 'M', '0', '1', 0};
  append32(Bytes, 1);
  append32(Bytes, Input.Bytes.size());
  append64(Bytes, Input.Witness);
  append32(Bytes, 1);
  append32(Bytes, Primes.size());
  const auto Hash = SHA256::hash(Input.Bytes);
  Bytes.insert(Bytes.end(), Hash.begin(), Hash.end());
  uint64_t State = Input.Witness ^ UINT64_C(0x465653574d303031);
  for (uint8_t Byte : Input.Bytes) {
    const uint8_t Share = splitmix(State);
    Bytes.push_back(Share);
    Bytes.push_back(Byte ^ Share);
  }
  return Bytes;
}

std::vector<uint8_t> globalBytes(GlobalVariable *Global) {
  if (!Global || !Global->hasInitializer())
    reject("carrier initializer is unavailable");
  auto *Data = dyn_cast<ConstantDataArray>(Global->getInitializer());
  if (!Data || !Data->getElementType()->isIntegerTy(8))
    reject("invalid carrier global type");
  const auto Raw = Data->getRawDataValues();
  return std::vector<uint8_t>(Raw.bytes_begin(), Raw.bytes_end());
}

std::vector<uint8_t> decodeCarrier(Module &M) {
  const auto Bytes = globalBytes(M.getNamedGlobal(CarrierName));
  const ArrayRef<uint8_t> View(Bytes);
  if (Bytes.size() < 64 ||
      StringRef(reinterpret_cast<const char *>(Bytes.data()), 8) !=
          StringRef("FVSWM01\0", 8) ||
      read32(View, 8) != 1 || read32(View, 24) != 1 ||
      read32(View, 28) != Primes.size())
    reject("unrecognized carrier structure");
  const uint32_t Size = read32(View, 12);
  if (Size == 0 || Size > MaxPacketBytes ||
      Bytes.size() != 64 + size_t(Size) * 2)
    reject("carrier bounds are invalid");
  std::vector<uint8_t> Decoded;
  for (uint32_t Index = 0; Index < Size; ++Index)
    Decoded.push_back(Bytes[64 + Index * 2] ^ Bytes[65 + Index * 2]);
  const auto Hash = SHA256::hash(Decoded);
  if (!std::equal(Hash.begin(), Hash.end(), Bytes.begin() + 32))
    reject("carrier checksum is invalid");
  return Decoded;
}

bool ownedName(StringRef Name) {
  for (StringRef Owned : OwnedNames)
    if (Name == Owned)
      return true;
  return false;
}

void replaceArray(Module &M, StringRef Name, ArrayRef<Constant *> Entries,
                  Type *ElementType, bool PreserveEmpty) {
  auto *Old = M.getNamedGlobal(Name);
  if (Entries.empty() && !PreserveEmpty) {
    if (Old) {
      if (!Old->use_empty())
        reject("compiler bookkeeping global has external users");
      Old->eraseFromParent();
    }
    return;
  }
  auto *Array = ArrayType::get(ElementType, Entries.size());
  auto *Initializer = ConstantArray::get(Array, Entries);
  auto *New = new GlobalVariable(M, Array, Old ? Old->isConstant() : false,
                                 Old ? Old->getLinkage()
                                     : GlobalValue::AppendingLinkage,
                                 Initializer, "", Old);
  if (Old) {
    New->copyAttributesFrom(Old);
    New->copyMetadata(Old, 0);
    New->takeName(Old);
    Old->replaceAllUsesWith(New);
    Old->eraseFromParent();
  } else {
    New->setName(Name);
    if (Name != "llvm.global_ctors")
      New->setSection("llvm.metadata");
  }
}

SmallVector<Constant *, 16> arrayEntries(Module &M, StringRef Name) {
  SmallVector<Constant *, 16> Entries;
  auto *Global = M.getNamedGlobal(Name);
  if (!Global)
    return Entries;
  auto *Array = dyn_cast_or_null<ConstantArray>(Global->getInitializer());
  if (!Array && Global->getInitializer()->isNullValue())
    return Entries;
  if (!Array)
    reject("unsupported compiler bookkeeping initializer");
  for (Value *Operand : Array->operands())
    Entries.push_back(cast<Constant>(Operand));
  return Entries;
}

std::string section(Module &M, StringRef Role) {
  const Triple Target(M.getTargetTriple());
  if (Target.isOSBinFormatMachO()) {
    if (Role == "carrier")
      return "__DATA_CONST,__fvwm";
    if (Role == "descriptor")
      return "__DATA_CONST,__fvcalc";
    if (Role == "seed")
      return "__DATA,__fvseed";
    if (Role == "values")
      return "__DATA,__fvdata";
    if (Role == "scratch")
      return "__DATA,__fvscratch";
    return "__TEXT,__fvcode";
  }
  if (Target.isOSBinFormatCOFF()) {
    if (Role == "code")
      return ".fvcode";
  } else if (!Target.isOSBinFormatELF()) {
    reject("this experimental pass supports ELF, COFF and Mach-O targets");
  }
  if (Role == "carrier")
    return ".fvwm";
  if (Role == "descriptor")
    return ".fvcalc";
  if (Role == "seed")
    return ".fvseed";
  if (Role == "values")
    return ".fvdata";
  if (Role == "scratch")
    return ".fvscr";
  return ".text.fvwm";
}

GlobalVariable *addGlobal(Module &M, StringRef Name, Constant *Initializer,
                          bool ConstantValue, StringRef Role,
                          unsigned Alignment) {
  auto *Global =
      new GlobalVariable(M, Initializer->getType(), ConstantValue,
                         GlobalValue::ExternalLinkage, Initializer, Name);
  Global->setSection(section(M, Role));
  Global->setAlignment(Align(Alignment));
  return Global;
}

void functionProperties(Module &M, Function &Function) {
  Function.addFnAttr(Attribute::NoInline);
  Function.addFnAttr(Attribute::OptimizeNone);
  Function.addFnAttr("fileveil.software.witness", "v1");
  Function.setSection(section(M, "code"));
  if (Triple(M.getTargetTriple()).isOSBinFormatCOFF() &&
      Function.getName() == ProbeName)
    Function.setDLLStorageClass(GlobalValue::DLLExportStorageClass);
}

struct MarkerInfo {
  std::string BaseHash;
  std::string PacketHash;
  bool HadConstructors;
  bool HadUsed;
  bool HadCompilerUsed;
};
struct CRTDescriptor {
  uint64_t Seed;
  std::array<uint32_t, 9> Factors{}, Offsets{};
  std::vector<uint8_t> Bytes;
};
CRTDescriptor descriptor(const Packet &Input) {
  uint64_t State = Input.Witness ^ UINT64_C(0x43525453454d3031);
  CRTDescriptor Result{
      splitmix(State), {}, {}, {'F', 'V', 'S', 'W', 'D', '0', '1', 0}};
  append32(Result.Bytes, 1);
  append32(Result.Bytes, Primes.size());
  append64(Result.Bytes, Result.Seed);
  for (size_t Index = 0; Index < Primes.size(); ++Index) {
    const uint32_t Prime = Primes[Index];
    Result.Factors[Index] = splitmix(State) % (Prime - 1) + 1;
    const uint64_t Product = ((Result.Seed ^ Input.Challenge) % Prime) *
                             Result.Factors[Index] % Prime;
    Result.Offsets[Index] = (Input.Witness % Prime + Prime - Product) % Prime;
    append32(Result.Bytes, Prime);
    append32(Result.Bytes, Result.Factors[Index]);
    append32(Result.Bytes, Result.Offsets[Index]);
  }
  return Result;
}
MarkerInfo markerInfo(Module &M) {
  auto *Metadata = M.getNamedMetadata(Marker);
  if (!Metadata || Metadata->getNumOperands() != 1 ||
      Metadata->getOperand(0)->getNumOperands() != 6)
    reject("controlled cleanup requires this pass's complete IR marker");
  auto *Node = Metadata->getOperand(0);
  auto Read = [&](unsigned Index) -> StringRef {
    auto *String = dyn_cast<MDString>(Node->getOperand(Index));
    if (!String)
      reject("invalid IR marker fields");
    return String->getString();
  };
  if (Read(0) != Marker || Read(1).size() != 64 || Read(2).size() != 64)
    reject("invalid IR marker identity");
  return {Read(1).str(), Read(2).str(), Read(3) == "1", Read(4) == "1",
          Read(5) == "1"};
}

bool mark(Module &M, const Packet &Input) {
  const std::string PacketHash = hex(SHA256::hash(Input.Bytes));
  const auto Descriptor = descriptor(Input);
  if (M.getNamedMetadata(Marker)) {
    const auto Existing = markerInfo(M);
    const auto Decoded = decodeCarrier(M);
    const auto Bytes = globalBytes(M.getNamedGlobal(CarrierName));
    if (Existing.PacketHash != PacketHash || Decoded != Input.Bytes ||
        read64(Bytes, 16) != Input.Witness ||
        globalBytes(M.getNamedGlobal(DescriptorName)) != Descriptor.Bytes)
      reject(
          "another marker is present; use an unmarked module for a new mark");
    return false;
  }
  for (const auto &Global : M.global_values()) {
    if (Global.getName().starts_with("__fileveil_swm_") ||
        Global.getName().starts_with(ProbeName))
      reject(
          "an existing user symbol conflicts with this pass's reserved names");
  }
  const MarkerInfo Info{moduleDigest(M), PacketHash,
                        M.getNamedGlobal("llvm.global_ctors") != nullptr,
                        M.getNamedGlobal("llvm.used") != nullptr,
                        M.getNamedGlobal("llvm.compiler.used") != nullptr};
  auto &Context = M.getContext();
  auto *I32 = Type::getInt32Ty(Context);
  auto *I64 = Type::getInt64Ty(Context);
  const auto Encoded = carrier(Input);
  auto *Carrier =
      addGlobal(M, CarrierName, ConstantDataArray::get(Context, Encoded), true,
                "carrier", 16);
  auto *Calc = addGlobal(M, DescriptorName,
                         ConstantDataArray::get(Context, Descriptor.Bytes),
                         true, "descriptor", 4);
  auto *SeedGlobal = addGlobal(
      M, SeedName, ConstantInt::get(I64, Descriptor.Seed), false, "seed", 8);
  auto *ValuesType = ArrayType::get(I32, Primes.size());
  auto *Values =
      addGlobal(M, ValuesName, ConstantAggregateZero::get(ValuesType), false,
                "values", 4);
  auto *Scratch =
      addGlobal(M, ScratchName, ConstantInt::get(I64, 0), false, "scratch", 8);
  auto *Probe = Function::Create(FunctionType::get(I32, {I32, I64}, false),
                                 GlobalValue::ExternalLinkage, ProbeName, M);
  functionProperties(M, *Probe);
  auto Argument = Probe->arg_begin();
  Value *Index = &*Argument++;
  Value *Challenge = &*Argument;
  auto *Entry = BasicBlock::Create(Context, "entry", Probe);
  auto *Invalid = BasicBlock::Create(Context, "invalid", Probe);
  IRBuilder<> Builder(Entry);
  auto *Switch = Builder.CreateSwitch(Index, Invalid, Primes.size());
  Builder.SetInsertPoint(Invalid);
  Builder.CreateRet(ConstantInt::get(I32, UINT32_MAX));
  for (unsigned Position = 0; Position < Primes.size(); ++Position) {
    auto *Calculate = BasicBlock::Create(Context, "residue", Probe);
    auto *Left = BasicBlock::Create(Context, "left", Probe);
    auto *Right = BasicBlock::Create(Context, "right", Probe);
    auto *Done = BasicBlock::Create(Context, "done", Probe);
    Switch->addCase(ConstantInt::get(I32, Position), Calculate);
    Builder.SetInsertPoint(Calculate);
    auto *SeedValue = Builder.CreateLoad(I64, SeedGlobal);
    SeedValue->setVolatile(true);
    auto *Prime = ConstantInt::get(I64, Primes[Position]);
    auto *Mixed =
        Builder.CreateURem(Builder.CreateXor(SeedValue, Challenge), Prime);
    auto *Product = Builder.CreateMul(
        Mixed, ConstantInt::get(I64, Descriptor.Factors[Position]));
    auto *Sum = Builder.CreateAdd(
        Product, ConstantInt::get(I64, Descriptor.Offsets[Position]));
    auto *Residue = Builder.CreateTrunc(Builder.CreateURem(Sum, Prime), I32);
    auto *Address = Builder.CreateInBoundsGEP(
        ValuesType, Values, {Builder.getInt32(0), Builder.getInt32(Position)});
    auto *Stored = Builder.CreateStore(Residue, Address);
    Stored->setVolatile(true);
    Stored->setAtomic(AtomicOrdering::Monotonic);
    Builder.CreateCondBr(
        Builder.CreateICmpEQ(Builder.CreateAnd(Residue, Builder.getInt32(1)),
                             Builder.getInt32(0)),
        Left, Right);
    Builder.SetInsertPoint(Left);
    auto *LeftStore =
        Builder.CreateStore(Builder.CreateZExt(Residue, I64), Scratch);
    LeftStore->setVolatile(true);
    LeftStore->setAtomic(AtomicOrdering::Monotonic);
    Builder.CreateBr(Done);
    Builder.SetInsertPoint(Right);
    auto *RightStore = Builder.CreateStore(
        Builder.CreateXor(Builder.CreateZExt(Residue, I64),
                          ConstantInt::get(I64, UINT64_C(0x9e3779b97f4a7c15))),
        Scratch);
    RightStore->setVolatile(true);
    RightStore->setAtomic(AtomicOrdering::Monotonic);
    Builder.CreateBr(Done);
    Builder.SetInsertPoint(Done);
    Builder.CreateRet(Residue);
  }
  auto *Constructor =
      Function::Create(FunctionType::get(Builder.getVoidTy(), false),
                       GlobalValue::InternalLinkage, ConstructorName, M);
  functionProperties(M, *Constructor);
  Builder.SetInsertPoint(BasicBlock::Create(Context, "entry", Constructor));
  for (unsigned Position = 0; Position < Primes.size(); ++Position)
    Builder.CreateCall(Probe,
                       {Builder.getInt32(Position), ConstantInt::get(I64, 0)});
  Builder.CreateRetVoid();

  auto Constructors = arrayEntries(M, "llvm.global_ctors");
  StructType *ConstructorType = nullptr;
  if (auto *Existing = M.getNamedGlobal("llvm.global_ctors"))
    ConstructorType = dyn_cast<StructType>(
        cast<ArrayType>(Existing->getValueType())->getElementType());
  if (!ConstructorType)
    ConstructorType =
        StructType::get(I32, Builder.getPtrTy(), Builder.getPtrTy());
  if (ConstructorType->getNumElements() != 3)
    reject("unsupported global constructor record");
  Constructors.push_back(ConstantStruct::get(
      ConstructorType, {Builder.getInt32(65535), Constructor,
                        ConstantPointerNull::get(Builder.getPtrTy())}));
  replaceArray(M, "llvm.global_ctors", Constructors, ConstructorType, true);
  auto Used = arrayEntries(M, "llvm.used");
  SmallVector<GlobalValue *, 7> RetainedValues{
      Carrier, Calc, SeedGlobal, Values, Scratch, Probe, Constructor};
  for (GlobalValue *Value : RetainedValues)
    Used.push_back(Value);
  replaceArray(M, "llvm.used", Used, Builder.getPtrTy(), true);
  auto *Metadata = M.getOrInsertNamedMetadata(Marker);
  Metadata->addOperand(MDNode::get(
      Context,
      {MDString::get(Context, Marker), MDString::get(Context, Info.BaseHash),
       MDString::get(Context, Info.PacketHash),
       MDString::get(Context, Info.HadConstructors ? "1" : "0"),
       MDString::get(Context, Info.HadUsed ? "1" : "0"),
       MDString::get(Context, Info.HadCompilerUsed ? "1" : "0")}));
  if (verifyModule(M, &errs()))
    reject("generated module failed LLVM verification");
  return true;
}

void filterBookkeeping(Module &M, StringRef Name, bool HadOriginal,
                       bool Constructors) {
  auto *Global = M.getNamedGlobal(Name);
  if (!Global)
    return;
  auto *Element = cast<ArrayType>(Global->getValueType())->getElementType();
  auto Entries = arrayEntries(M, Name);
  SmallVector<Constant *, 16> Retained;
  for (Constant *Entry : Entries) {
    Value *Target = Constructors ? Entry->getOperand(1) : Entry;
    auto *Value = dyn_cast<GlobalValue>(Target->stripPointerCasts());
    if (!Value || !ownedName(Value->getName()))
      Retained.push_back(Entry);
  }
  replaceArray(M, Name, Retained, Element, HadOriginal);
}

class WatermarkPass : public PassInfoMixin<WatermarkPass> {
  std::string Operation;

public:
  explicit WatermarkPass(StringRef Operation) : Operation(Operation.str()) {}
  static bool isRequired() { return true; }
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    if (Operation == "automatic") {
      const char *Selected = std::getenv("FILEVEIL_SOFTWARE_MODULE");
      if (Selected && *Selected) {
        if (M.getSourceFileName() != Selected &&
            sys::path::filename(M.getSourceFileName()) != Selected)
          return PreservedAnalyses::all();
      } else {
        auto *Main = M.getFunction("main");
        if (!Main || Main->isDeclaration())
          return PreservedAnalyses::all();
      }
      return mark(M, readPacket()) ? PreservedAnalyses::none()
                                   : PreservedAnalyses::all();
    }
    if (Operation == "inspect") {
      json::Object Result{{"schema", "fileveil.software.ir-inspection.v1"},
                          {"canonical_ir_sha256", moduleDigest(M)},
                          {"marked", M.getNamedMetadata(Marker) != nullptr}};
      if (M.getNamedMetadata(Marker)) {
        const auto Info = markerInfo(M);
        const auto Packet = decodeCarrier(M);
        Result["base_ir_sha256"] = Info.BaseHash;
        Result["packet_sha256"] = Info.PacketHash;
        Result["packet_hex"] = hex(Packet);
      }
      outs() << formatv("{0}\n", json::Value(std::move(Result)));
      return PreservedAnalyses::all();
    }
    if (Operation == "mark")
      return mark(M, readPacket()) ? PreservedAnalyses::none()
                                   : PreservedAnalyses::all();
    if (!M.getNamedMetadata(Marker))
      reject("module has no recognized FileVeil IR marker");
    const auto Info = markerInfo(M);
    if (hex(SHA256::hash(decodeCarrier(M))) != Info.PacketHash)
      reject("IR marker and packet hashes differ");
    for (StringRef Name : {ConstructorName, ProbeName}) {
      auto *Function = M.getFunction(Name);
      if (!Function || Function->getFnAttribute("fileveil.software.witness")
                               .getValueAsString() != "v1")
        reject("owned witness function is missing or changed");
    }
    filterBookkeeping(M, "llvm.global_ctors", Info.HadConstructors, true);
    filterBookkeeping(M, "llvm.used", Info.HadUsed, false);
    filterBookkeeping(M, "llvm.compiler.used", Info.HadCompilerUsed, false);
    for (StringRef Name : OwnedNames) {
      if (auto *Function = M.getFunction(Name))
        Function->dropAllReferences();
      else if (auto *Global = M.getNamedGlobal(Name))
        Global->dropAllReferences();
    }
    M.eraseNamedMetadata(M.getNamedMetadata(Marker));
    for (StringRef Name : OwnedNames) {
      auto *Global = M.getNamedValue(Name);
      if (Global)
        Global->removeDeadConstantUsers();
      if (!Global)
        reject("an owned watermark symbol is missing; cleanup is protected");
      if (!Global->use_empty())
        reject(Twine("user code references owned symbol ") + Name +
               "; cleanup is protected");
    }
    for (StringRef Name : OwnedNames)
      M.getNamedValue(Name)->eraseFromParent();
    if (verifyModule(M, &errs()))
      reject("cleaned module failed LLVM verification");
    const std::string Restored = moduleDigest(M);
    outs() << formatv(
        "{0}\n", json::Value(json::Object{
                     {"schema", "fileveil.software.ir-clean.v1"},
                     {"base_ir_sha256", Info.BaseHash},
                     {"clean_ir_sha256", Restored},
                     {"canonical_base_restored", Restored == Info.BaseHash},
                     {"llvm_ir_verified", true}}));
    return PreservedAnalyses::none();
  }
};
} // namespace

#if defined(FILEVEIL_STANDALONE_DRIVER)
int main(int Argc, char **Argv) {
  InitLLVM Initialization(Argc, Argv);
  if (Argc != 5 && Argc != 7)
    reject("driver requires --operation, --input and an optional --output");
  StringRef Operation, Input, Output;
  for (int Index = 1; Index < Argc; Index += 2) {
    const StringRef Name(Argv[Index]);
    const StringRef Value(Argv[Index + 1]);
    StringRef *Selected = nullptr;
    if (Name == "--operation")
      Selected = &Operation;
    else if (Name == "--input")
      Selected = &Input;
    else if (Name == "--output")
      Selected = &Output;
    else
      reject("driver received an unsupported argument");
    if (!Selected->empty() || Value.empty())
      reject("driver arguments must be unique and nonempty");
    *Selected = Value;
  }
  if (Operation != "mark" && Operation != "clean" && Operation != "inspect")
    reject("driver operation must be mark, clean or inspect");
  if (Input.empty() || !sys::path::is_absolute(Input))
    reject("driver input must be an absolute file path");
  if ((Operation == "inspect") != Output.empty())
    reject("mark and clean require output; inspect cannot write a file");
  if (!Output.empty() && !sys::path::is_absolute(Output))
    reject("driver output must be an absolute file path");
  sys::fs::file_status Status;
  if (sys::fs::status(Input, Status) || !sys::fs::is_regular_file(Status) ||
      Status.getSize() > 64 * 1024 * 1024)
    reject("driver input must be a regular IR file within 64 MiB");
  auto Buffer = MemoryBuffer::getFile(Input);
  if (!Buffer || (*Buffer)->getBufferSize() > 64 * 1024 * 1024)
    reject("driver could not read bounded IR input");
  LLVMContext Context;
  SMDiagnostic Diagnostic;
  auto Module = parseIR((*Buffer)->getMemBufferRef(), Diagnostic, Context);
  if (!Module) {
    Diagnostic.print("FileVeilWatermarkDriver", errs());
    return 2;
  }
  if (verifyModule(*Module, &errs()))
    reject("driver input failed LLVM verification");
  ModuleAnalysisManager Analyses;
  WatermarkPass(Operation).run(*Module, Analyses);
  if (verifyModule(*Module, &errs()))
    reject("driver result failed LLVM verification");
  if (!Output.empty()) {
    int Descriptor;
    if (sys::fs::openFileForWrite(Output, Descriptor, sys::fs::CD_CreateNew,
                                 sys::fs::OF_Text))
      reject("driver output must be a new writable file");
    raw_fd_ostream Stream(Descriptor, true);
    Module->print(Stream, nullptr);
    Stream.flush();
    if (Stream.has_error())
      reject("driver could not complete IR output");
  }
  return 0;
}
#else
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "FileVeilWatermark", "1.0.0",
          [](PassBuilder &Builder) {
            Builder.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &Passes,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  for (StringRef Operation : {"mark", "clean", "inspect"}) {
                    if (Name == (Twine("fileveil-") + Operation).str()) {
                      Passes.addPass(WatermarkPass(Operation));
                      return true;
                    }
                  }
                  return false;
                });
            Builder.registerPipelineStartEPCallback(
                [](ModulePassManager &Passes, OptimizationLevel) {
                  const char *Packet = std::getenv("FILEVEIL_SOFTWARE_PACKET");
                  if (Packet && *Packet)
                    Passes.addPass(WatermarkPass("automatic"));
                });
          }};
}
#endif

// FVPROV1 28559 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlMWM0MjNmOWE4OGIzYWFhN2MwMzU3ODJhNjM5NjAxNjIzODIxYWMxMmQ0NGQ5MDE1MjIyNmJhZGFjZjI0YWQ1IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3NvZnR3YXJlLXdhdGVybWFyay9GaWxlVmVpbFdhdGVybWFyay5jcHAifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI4ZWVkOTc2NGQ0YWFmMGZhMGE5NTNmMTg2NzlhYTZkNmY1NjgzODg0MjY5MTBhZjc5ZjNkMTE1MTQ0ZDNhZjA0NzViYTU0MmVmZTllNjYzODUwYjIwMWY1MTk4ZjNjMjNlZGFhYjQzMDU0NjZmZDA2MTZmOWZiMzUyM2IyMmEwZiJ9XX1d FVPROV1-END
