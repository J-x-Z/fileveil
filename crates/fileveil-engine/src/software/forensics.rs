// SPDX-License-Identifier: MPL-2.0
//! Bounded syntactic CFG and register-use candidates from llvm-objdump text.
//! Register families and selected opcode effects are heuristic. This module
//! neither executes instructions nor identifies an unknown watermark protocol.
use fileveil_core::digest;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MAX_TEXT: usize = 2 * 1024 * 1024;
const MAX_LINES: usize = 120_000;
const MAX_LINE: usize = 4096;
const MAX_INSTRUCTIONS: usize = 100_000;
const MAX_BLOCKS: usize = 8192;
const MAX_DETAILS: usize = 4096;
const MAX_BLOCK_DETAILS: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Architecture {
    Arm64,
    X86,
    Unknown,
}
impl Architecture {
    fn label(self) -> &'static str {
        match self {
            Self::Arm64 => "aarch64",
            Self::X86 => "x86_64",
            Self::Unknown => "unknown",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
    Next,
    Conditional,
    Jump,
    Call,
    Return,
    Trap,
}
impl Flow {
    fn label(self) -> &'static str {
        match self {
            Self::Next => "fallthrough",
            Self::Conditional => "conditional_branch",
            Self::Jump => "jump",
            Self::Call => "call",
            Self::Return => "return",
            Self::Trap => "trap_or_system_transfer",
        }
    }
    fn falls_through(self) -> bool {
        matches!(self, Self::Next | Self::Conditional | Self::Call)
    }
}
struct Instruction {
    address: u64,
    function: usize,
    architecture: Architecture,
    mnemonic: String,
    operands: Vec<String>,
    flow: Flow,
    target: Option<u64>,
    effects: Effects,
}
#[derive(Default)]
struct Effects {
    defs: BTreeSet<String>,
    uses: BTreeSet<String>,
    known: bool,
}
#[derive(Serialize)]
struct Block {
    id: usize,
    function: usize,
    start: u64,
    end: u64,
    instruction_count: usize,
    normalized_sha256: String,
    literal_sha256: String,
    terminator: &'static str,
    unknown_effects: usize,
    definitions: usize,
    uses: usize,
    live_in_candidates: BTreeSet<String>,
}
#[derive(Serialize)]
struct Edge {
    from_block: usize,
    from: u64,
    to: Option<u64>,
    to_block: Option<usize>,
    kind: &'static str,
    target_scope: &'static str,
}
#[derive(Serialize)]
struct DefUse {
    block: usize,
    register: String,
    definition: u64,
    use_at: u64,
}
struct Parsed {
    instructions: Vec<Instruction>,
    functions: usize,
    malformed: usize,
    truncated: bool,
}

// Only these opcode families receive register-effect candidates. The remaining
// instructions stay unknown and stop reaching-definition propagation.
fn listed(value: &str, choices: &str) -> bool {
    choices
        .split_ascii_whitespace()
        .any(|choice| choice == value)
}

fn arm_register(token: &str) -> Option<(String, u16)> {
    let token = token
        .trim_start_matches('%')
        .split('.')
        .next()?
        .to_ascii_lowercase();
    match token.as_str() {
        "sp" => return Some(("sp".into(), 64)),
        "wsp" => return Some(("sp".into(), 32)),
        "fp" => return Some(("x29".into(), 64)),
        "lr" => return Some(("x30".into(), 64)),
        "nzcv" => return Some(("nzcv".into(), 4)),
        "xzr" | "wzr" => return None,
        _ => {}
    }
    let (prefix, number) = token.split_at_checked(1)?;
    let number = number.parse::<u8>().ok()?;
    match prefix {
        "x" if number <= 30 => Some((format!("x{number}"), 64)),
        "w" if number <= 30 => Some((format!("x{number}"), 32)),
        "v" | "q" if number <= 31 => Some((format!("v{number}"), 128)),
        "d" if number <= 31 => Some((format!("v{number}"), 64)),
        "s" if number <= 31 => Some((format!("v{number}"), 32)),
        "h" if number <= 31 => Some((format!("v{number}"), 16)),
        "b" if number <= 31 => Some((format!("v{number}"), 8)),
        _ => None,
    }
}
fn x86_register(token: &str) -> Option<(String, u16)> {
    let token = token.trim_start_matches('%').to_ascii_lowercase();
    let groups = [
        ("rax", ["rax", "eax", "ax", "al", "ah"]),
        ("rbx", ["rbx", "ebx", "bx", "bl", "bh"]),
        ("rcx", ["rcx", "ecx", "cx", "cl", "ch"]),
        ("rdx", ["rdx", "edx", "dx", "dl", "dh"]),
        ("rsi", ["rsi", "esi", "si", "sil", ""]),
        ("rdi", ["rdi", "edi", "di", "dil", ""]),
        ("rsp", ["rsp", "esp", "sp", "spl", ""]),
        ("rbp", ["rbp", "ebp", "bp", "bpl", ""]),
        ("rip", ["rip", "eip", "ip", "", ""]),
    ];
    for (canonical, aliases) in groups {
        if let Some(index) = aliases
            .iter()
            .position(|alias| !alias.is_empty() && *alias == token)
        {
            return Some((canonical.into(), [64, 32, 16, 8, 8][index]));
        }
    }
    if listed(token.as_str(), "eflags rflags") {
        return Some(("rflags".into(), 64));
    }
    for (prefix, width) in [
        ("xmm", 128),
        ("ymm", 256),
        ("zmm", 512),
        ("mm", 64),
        ("k", 64),
    ] {
        if let Some(number) = token
            .strip_prefix(prefix)
            .and_then(|value| value.parse::<u8>().ok())
            .filter(|number| *number <= 31)
        {
            let family = if matches!(prefix, "xmm" | "ymm" | "zmm") {
                "v"
            } else {
                prefix
            };
            return Some((format!("{family}{number}"), width));
        }
    }
    let rest = token.strip_prefix('r')?;
    let (number, width) = if let Some(number) = rest.strip_suffix('d') {
        (number, 32)
    } else if let Some(number) = rest.strip_suffix('w') {
        (number, 16)
    } else if let Some(number) = rest.strip_suffix('b') {
        (number, 8)
    } else {
        (rest, 64)
    };
    let number = number.parse::<u8>().ok()?;
    (8..=15)
        .contains(&number)
        .then(|| (format!("r{number}"), width))
}
fn tokens(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '%'))
        })
        .filter(|token| !token.is_empty())
}
fn registers(value: &str, architecture: Architecture) -> BTreeSet<String> {
    tokens(value)
        .filter_map(|token| match architecture {
            Architecture::Arm64 => arm_register(token),
            Architecture::X86 => x86_register(token),
            Architecture::Unknown => None,
        })
        .map(|value| value.0)
        .collect()
}
fn architecture(mnemonic: &str, operands: &[String]) -> Architecture {
    let arm = operands
        .iter()
        .flat_map(|value| tokens(value))
        .any(|token| arm_register(token).is_some() && !matches!(token, "sp" | "fp" | "lr"));
    let x86 = operands
        .iter()
        .flat_map(|value| tokens(value))
        .any(|token| x86_register(token).is_some() && token != "sp");
    match (arm, x86) {
        (true, false) => Architecture::Arm64,
        (false, true) => Architecture::X86,
        (true, true) => Architecture::Unknown,
        _ if listed(mnemonic, "b bl br blr cbz cbnz tbz tbnz adrp stp ldp")
            || mnemonic.starts_with("b.") =>
        {
            Architecture::Arm64
        }
        _ if mnemonic.starts_with('j') || listed(mnemonic, "call callq retq pushq popq") => {
            Architecture::X86
        }
        _ => Architecture::Unknown,
    }
}
fn operands(value: &str) -> Option<Vec<String>> {
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut result = Vec::new();
    for (offset, character) in value.char_indices() {
        match character {
            '[' | '(' | '{' => {
                depth += 1;
                if depth > 16 {
                    return None;
                }
            }
            ']' | ')' | '}' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => {
                result.push(value[start..offset].trim().into());
                start = offset + 1;
            }
            _ => {}
        }
    }
    if depth != 0 || result.len() > 16 {
        return None;
    }
    if !value[start..].trim().is_empty() {
        result.push(value[start..].trim().into())
    }
    Some(result)
}
fn flow(mnemonic: &str) -> Flow {
    if listed(mnemonic, "b b.al br braa brab jmp jmpq") {
        return Flow::Jump;
    }
    if listed(mnemonic, "bl blr blraa blrab call callq") {
        return Flow::Call;
    }
    if listed(mnemonic, "ret retq retaa retab iret iretq") {
        return Flow::Return;
    }
    if listed(mnemonic, "brk hlt ud2 int3 syscall sysenter svc hvc smc") {
        return Flow::Trap;
    }
    if mnemonic.starts_with("b.")
        || listed(
            mnemonic,
            "cbz cbnz tbz tbnz ja jae jb jbe jc jcxz jecxz jrcxz je jz jg jge jl jle jna jnae jnb jnbe jnc jne jng jnge jnl jnle jno jnp jns jnz jo jp jpe jpo js loop loope loopne loopz loopnz",
        )
    {
        return Flow::Conditional;
    }
    Flow::Next
}
fn target(operands: &[String], flow: Flow) -> Option<u64> {
    if !matches!(flow, Flow::Jump | Flow::Conditional | Flow::Call) {
        return None;
    }
    let last = operands.last()?.trim();
    if last.starts_with('*') || last.contains(['[', '(']) {
        return None;
    }
    let token = last.split_whitespace().next()?.trim_start_matches('#');
    let token = token.strip_prefix("0x").unwrap_or(token);
    if token.is_empty() || token.len() > 16 || !token.bytes().all(|value| value.is_ascii_hexdigit())
    {
        return None;
    }
    u64::from_str_radix(token, 16).ok()
}
fn parse(text: &str) -> Parsed {
    let mut end = text.len().min(MAX_TEXT);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut result = Parsed {
        instructions: Vec::new(),
        functions: 0,
        malformed: 0,
        truncated: end < text.len(),
    };
    let mut function = 0usize;
    let lower = text[..end]
        .lines()
        .take(16)
        .filter(|line| line.contains("file format") || line.contains("architecture:"))
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let header = if lower.contains("aarch64") || lower.contains("arm64") {
        Architecture::Arm64
    } else if lower.contains("x86-64") || lower.contains("x86_64") {
        Architecture::X86
    } else {
        Architecture::Unknown
    };
    let mut inherited = header;
    for (line_number, line) in text[..end].lines().enumerate() {
        if line_number == MAX_LINES {
            result.truncated = true;
            break;
        }
        if line.len() > MAX_LINE {
            result.malformed += 1;
            function += 1;
            continue;
        }
        let line = line.trim();
        if line.starts_with("Disassembly of section") || line.ends_with(">:") {
            function += 1;
            if line.ends_with(">:") {
                result.functions += 1
            }
            inherited = header;
            continue;
        }
        let Some((address, body)) = line.split_once(':') else {
            continue;
        };
        let Ok(address) = u64::from_str_radix(address.trim().trim_start_matches("0x"), 16) else {
            continue;
        };
        let mut pieces = body.split_whitespace();
        let mnemonic = pieces.find(|token| {
            !((token.len() == 2 || token.len() == 8)
                && token.bytes().all(|value| value.is_ascii_hexdigit()))
        });
        let Some(mnemonic) = mnemonic else {
            result.malformed += 1;
            function += 1;
            continue;
        };
        if mnemonic.len() > 32
            || !mnemonic
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_'))
        {
            result.malformed += 1;
            function += 1;
            continue;
        }
        let mnemonic = mnemonic.to_ascii_lowercase();
        let joined = pieces.collect::<Vec<_>>().join(" ");
        let comment = joined
            .find("//")
            .or_else(|| joined.find(" ;"))
            .or_else(|| joined.find(" # "));
        let joined = comment.map(|index| &joined[..index]).unwrap_or(&joined);
        let mut plain = String::new();
        let mut annotation = false;
        for character in joined.chars() {
            if character == '<' {
                annotation = true
            } else if character == '>' {
                annotation = false
            } else if !annotation {
                plain.push(character)
            }
        }
        let Some(operands) = operands(&plain) else {
            result.malformed += 1;
            function += 1;
            continue;
        };
        let guessed = architecture(&mnemonic, &operands);
        let mixed = operands
            .iter()
            .flat_map(|value| tokens(value))
            .any(|token| arm_register(token).is_some() && !matches!(token, "sp" | "fp" | "lr"))
            && operands
                .iter()
                .flat_map(|value| tokens(value))
                .any(|token| x86_register(token).is_some() && token != "sp");
        let architecture = if mixed {
            Architecture::Unknown
        } else if guessed == Architecture::Unknown {
            inherited
        } else {
            guessed
        };
        if guessed != Architecture::Unknown {
            inherited = guessed
        }
        let flow = flow(&mnemonic);
        let target = target(&operands, flow);
        let effects = effects(&mnemonic, &operands, architecture, flow);
        result.instructions.push(Instruction {
            address,
            function,
            architecture,
            mnemonic,
            operands,
            flow,
            target,
            effects,
        });
        if result.instructions.len() == MAX_INSTRUCTIONS {
            result.truncated = true;
            break;
        }
    }
    result
}
fn read_operands(effect: &mut Effects, operands: &[String], architecture: Architecture) {
    for operand in operands {
        effect.uses.extend(registers(operand, architecture));
    }
}
fn destination(effect: &mut Effects, operand: &str, architecture: Architecture, read_old: bool) {
    let memory = operand.contains(['[', '(']);
    let regs = registers(operand, architecture);
    if memory {
        effect.uses.extend(regs);
        return;
    }
    effect.defs.extend(regs.clone());
    let partial = architecture == Architecture::X86
        && tokens(operand)
            .filter_map(x86_register)
            .any(|(_, width)| width < 32);
    if read_old || partial {
        effect.uses.extend(regs)
    }
}
fn arm_effects(mnemonic: &str, operands: &[String], flow: Flow) -> Effects {
    let mut effect = Effects::default();
    if flow == Flow::Call {
        effect.defs.insert("x30".into());
        return effect;
    }
    if matches!(flow, Flow::Conditional | Flow::Jump | Flow::Return) {
        read_operands(&mut effect, operands, Architecture::Arm64);
        if mnemonic.starts_with("b.") {
            effect.uses.insert("nzcv".into());
        }
        if flow == Flow::Return && operands.is_empty() {
            effect.uses.insert("x30".into());
        }
        effect.known = !listed(mnemonic, "retaa retab braa brab");
        return effect;
    }
    if listed(mnemonic, "nop hint") {
        effect.known = true;
        return effect;
    }
    if listed(mnemonic, "cmp cmn tst") {
        read_operands(&mut effect, operands, Architecture::Arm64);
        effect.defs.insert("nzcv".into());
        effect.known = true;
        return effect;
    }
    let loads = listed(
        mnemonic,
        "ldr ldrb ldrh ldrsb ldrsh ldrsw ldur ldurb ldurh ldursw ldar ldarb ldarh ldxr ldaxr",
    );
    let pairs = listed(mnemonic, "ldp ldnp ldpsw");
    let stores = listed(
        mnemonic,
        "str strb strh stur sturb sturh stp stnp stlr stlrb stlrh",
    );
    if loads || pairs || stores {
        let destinations = if pairs {
            2
        } else if loads {
            1
        } else {
            0
        };
        if operands.len() <= destinations {
            return effect;
        }
        for operand in &operands[..destinations] {
            destination(&mut effect, operand, Architecture::Arm64, false)
        }
        read_operands(&mut effect, &operands[destinations..], Architecture::Arm64);
        if let Some(memory) = operands.iter().position(|operand| operand.contains('['))
            && (operands[memory].ends_with('!') || memory + 1 < operands.len())
        {
            effect
                .defs
                .extend(registers(&operands[memory], Architecture::Arm64));
        }
        effect.known = true;
        return effect;
    }
    let simple = listed(
        mnemonic,
        "mov movz movn movk adr adrp add adds sub subs adc adcs sbc sbcs and ands orr orn eor eon bic bics mul madd msub udiv sdiv lsl lsr asr ror extr neg negs mvn ubfx sbfx bfi bfxil ubfiz sbfiz uxtb uxth uxtw sxtb sxth sxtw rev rev16 rev32 clz rbit cset csetm csel csinc csinv csneg",
    );
    if simple && !operands.is_empty() {
        destination(
            &mut effect,
            &operands[0],
            Architecture::Arm64,
            listed(mnemonic, "movk bfi bfxil"),
        );
        read_operands(&mut effect, &operands[1..], Architecture::Arm64);
        if listed(mnemonic, "adds subs adcs sbcs ands bics negs") {
            effect.defs.insert("nzcv".into());
        }
        if listed(
            mnemonic,
            "adc adcs sbc sbcs cset csetm csel csinc csinv csneg",
        ) {
            effect.uses.insert("nzcv".into());
        }
        effect.known = true;
    }
    effect
}
fn x86_base(mnemonic: &str) -> &str {
    let bases = [
        "mov", "movabs", "lea", "add", "adc", "sub", "sbb", "xor", "or", "and", "cmp", "test",
        "shl", "sal", "shr", "sar", "rol", "ror", "imul", "mul", "idiv", "div", "inc", "dec",
        "neg", "not", "push", "pop", "xchg",
    ];
    for base in bases {
        if mnemonic == base
            || mnemonic
                .strip_prefix(base)
                .is_some_and(|suffix| matches!(suffix, "b" | "w" | "l" | "q"))
        {
            return base;
        }
    }
    mnemonic
}
fn x86_effects(mnemonic: &str, operands: &[String], flow: Flow) -> Effects {
    let mut effect = Effects::default();
    let base = x86_base(mnemonic);
    if flow == Flow::Call {
        read_operands(&mut effect, operands, Architecture::X86);
        return effect;
    }
    if flow == Flow::Return {
        effect.uses.insert("rsp".into());
        effect.defs.insert("rsp".into());
        effect.known = listed(mnemonic, "ret retq");
        return effect;
    }
    if matches!(flow, Flow::Conditional | Flow::Jump) {
        read_operands(&mut effect, operands, Architecture::X86);
        if listed(mnemonic, "jcxz jecxz jrcxz loop loope loopne loopz loopnz") {
            effect.uses.insert("rcx".into());
            if mnemonic.starts_with("loop") {
                effect.defs.insert("rcx".into());
            }
        }
        if flow == Flow::Conditional && !listed(mnemonic, "jcxz jecxz jrcxz loop") {
            effect.uses.insert("rflags".into());
        }
        effect.known = true;
        return effect;
    }
    if listed(mnemonic, "nop nopl nopw endbr64 endbr32") {
        effect.known = true;
        return effect;
    }
    if listed(base, "cmp test") {
        read_operands(&mut effect, operands, Architecture::X86);
        effect.defs.insert("rflags".into());
        effect.known = true;
        return effect;
    }
    if listed(base, "push pop") && operands.len() == 1 {
        effect.uses.insert("rsp".into());
        effect.defs.insert("rsp".into());
        if base == "push" {
            read_operands(&mut effect, operands, Architecture::X86)
        } else {
            destination(&mut effect, &operands[0], Architecture::X86, false)
        }
        effect.known = true;
        return effect;
    }
    let simple = listed(
        base,
        "mov movabs lea add adc sub sbb xor or and shl sal shr sar rol ror imul inc dec neg not xchg",
    );
    let conditional = mnemonic.starts_with("cmov") || mnemonic.starts_with("set");
    if (!simple && !conditional) || operands.is_empty() || (base == "imul" && operands.len() == 1) {
        return effect;
    }
    let att = operands
        .iter()
        .any(|operand| operand.contains('%') || operand.starts_with('$'));
    let index = if att { operands.len() - 1 } else { 0 };
    let read_old = !listed(base, "mov movabs lea") && !mnemonic.starts_with("set");
    for (position, operand) in operands.iter().enumerate() {
        if position == index {
            destination(&mut effect, operand, Architecture::X86, read_old)
        } else {
            effect.uses.extend(registers(operand, Architecture::X86));
        }
    }
    if base == "xchg" {
        for operand in operands {
            destination(&mut effect, operand, Architecture::X86, true)
        }
    }
    if listed(base, "adc sbb") || conditional {
        effect.uses.insert("rflags".into());
    }
    if !listed(base, "mov movabs lea not xchg") && !conditional {
        effect.defs.insert("rflags".into());
    }
    effect.known = true;
    effect
}
fn effects(mnemonic: &str, operands: &[String], architecture: Architecture, flow: Flow) -> Effects {
    match architecture {
        Architecture::Arm64 => arm_effects(mnemonic, operands, flow),
        Architecture::X86 => x86_effects(mnemonic, operands, flow),
        Architecture::Unknown => Effects::default(),
    }
}

fn consecutive(left: &Instruction, right: &Instruction) -> bool {
    let distance = right.address.checked_sub(left.address);
    left.function == right.function
        && left.architecture == right.architecture
        && distance.is_some_and(|distance| {
            distance > 0
                && distance
                    <= if left.architecture == Architecture::Arm64 {
                        4
                    } else {
                        15
                    }
        })
}
fn number(token: &str) -> bool {
    let token = token.trim_start_matches(['#', '$', '-', '+']);
    !token.is_empty()
        && (token.strip_prefix("0x").is_some_and(|value| {
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) || token.bytes().all(|byte| byte.is_ascii_digit()))
}
fn normalized_operand(
    value: &str,
    architecture: Architecture,
    aliases: &mut BTreeMap<String, usize>,
    literals: &mut Vec<String>,
) -> String {
    let mut output = String::new();
    let mut token = String::new();
    let flush = |token: &mut String,
                 output: &mut String,
                 aliases: &mut BTreeMap<String, usize>,
                 literals: &mut Vec<String>| {
        if token.is_empty() {
            return;
        }
        let register = match architecture {
            Architecture::Arm64 => arm_register(token),
            Architecture::X86 => x86_register(token),
            Architecture::Unknown => None,
        };
        if let Some((register, width)) = register {
            if matches!(register.as_str(), "sp" | "rsp" | "rip" | "nzcv" | "rflags") {
                output.push_str(&format!("{register}:{width}"));
            } else {
                let next = aliases.len();
                let index = *aliases.entry(register).or_insert(next);
                output.push_str(&format!("r{index}:{width}"));
            }
        } else if number(token) {
            literals.push(token.to_ascii_lowercase());
            output.push_str("imm");
        } else if listed(
            token.as_str(),
            "eq ne cs hs cc lo mi pl vs vc hi ls ge lt gt le lsl lsr asr ror uxtw sxtw sxtx",
        ) {
            output.push_str(token);
        } else {
            output.push_str("symbol");
        }
        token.clear();
    };
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '%') {
            token.push(character)
        } else {
            flush(&mut token, &mut output, aliases, literals);
            if matches!(character, '[' | ']' | '(' | ')' | '+' | '-' | '*' | '!') {
                output.push(character)
            }
        }
    }
    flush(&mut token, &mut output, aliases, literals);
    output
}
fn normalized_instruction(
    instruction: &Instruction,
    aliases: &mut BTreeMap<String, usize>,
    literals: &mut Vec<String>,
) -> String {
    let mnemonic = if instruction.architecture == Architecture::X86 {
        x86_base(&instruction.mnemonic)
    } else {
        &instruction.mnemonic
    };
    let operands = instruction
        .operands
        .iter()
        .enumerate()
        .map(|(index, operand)| {
            if index + 1 == instruction.operands.len() && instruction.target.is_some() {
                "target".into()
            } else {
                normalized_operand(operand, instruction.architecture, aliases, literals)
            }
        })
        .collect::<Vec<String>>();
    format!("{mnemonic} {}", operands.join(","))
}
fn resolve_target(
    local: &BTreeMap<(usize, u64), Option<usize>>,
    global: &BTreeMap<u64, Option<usize>>,
    instruction: &Instruction,
) -> Option<usize> {
    let target = instruction.target?;
    if let Some(local) = local.get(&(instruction.function, target)) {
        return *local;
    }
    global.get(&target).copied().flatten()
}

/// Returned details are bounded. Fingerprints and counts cover the parsed range.
pub(super) fn analyze(text: &str) -> Value {
    let mut parsed = parse(text);
    let mut leaders = BTreeSet::new();
    if !parsed.instructions.is_empty() {
        leaders.insert(0usize);
    }
    let mut targets = BTreeMap::new();
    let mut local = BTreeMap::new();
    let mut global = BTreeMap::new();
    for (index, instruction) in parsed.instructions.iter().enumerate() {
        local
            .entry((instruction.function, instruction.address))
            .and_modify(|value| *value = None)
            .or_insert(Some(index));
        global
            .entry(instruction.address)
            .and_modify(|value| *value = None)
            .or_insert(Some(index));
    }
    for (index, instruction) in parsed.instructions.iter().enumerate() {
        if index > 0 && !consecutive(&parsed.instructions[index - 1], instruction) {
            leaders.insert(index);
        }
        if instruction.flow != Flow::Next && index + 1 < parsed.instructions.len() {
            leaders.insert(index + 1);
        }
        if let Some(target) = resolve_target(&local, &global, instruction) {
            leaders.insert(target);
            targets.insert(index, target);
        }
    }
    if leaders.len() > MAX_BLOCKS
        && let Some(boundary) = leaders.iter().nth(MAX_BLOCKS).copied()
    {
        parsed.instructions.truncate(boundary);
        leaders.retain(|index| *index < boundary);
        parsed.truncated = true;
    }
    let starts = leaders.into_iter().collect::<Vec<_>>();
    let mut instruction_blocks = vec![0usize; parsed.instructions.len()];
    for (block, start) in starts.iter().enumerate() {
        let end = starts
            .get(block + 1)
            .copied()
            .unwrap_or(parsed.instructions.len());
        instruction_blocks[*start..end].fill(block);
    }
    let mut blocks = Vec::new();
    let mut links = Vec::new();
    let mut link_count = 0usize;
    let mut unknown = 0usize;
    let mut normalized = Vec::new();
    let mut literals = Vec::new();
    let mut unknown_opcodes = BTreeMap::<String, usize>::new();
    for (id, start) in starts.iter().enumerate() {
        let end = starts
            .get(id + 1)
            .copied()
            .unwrap_or(parsed.instructions.len());
        let slice = &parsed.instructions[*start..end];
        let mut aliases = BTreeMap::new();
        let mut reaching = BTreeMap::<String, u64>::new();
        let mut block_normalized = Vec::new();
        let mut block_literals = Vec::new();
        let mut block_unknown = 0usize;
        let mut definitions = 0usize;
        let mut uses = 0usize;
        let mut live_in = BTreeSet::new();
        for instruction in slice {
            block_normalized.push(normalized_instruction(
                instruction,
                &mut aliases,
                &mut block_literals,
            ));
            if !instruction.effects.known {
                block_unknown += 1;
                unknown += 1;
                if unknown_opcodes.len() < 64 || unknown_opcodes.contains_key(&instruction.mnemonic)
                {
                    *unknown_opcodes
                        .entry(instruction.mnemonic.clone())
                        .or_default() += 1;
                }
                // Unknown operations and calls are conservative barriers. No
                // reaching-definition claim crosses their unmodeled effects.
                reaching.clear();
                continue;
            }
            definitions += instruction.effects.defs.len();
            uses += instruction.effects.uses.len();
            for register in &instruction.effects.uses {
                if let Some(definition) = reaching.get(register) {
                    link_count += 1;
                    if links.len() < MAX_DETAILS {
                        links.push(DefUse {
                            block: id,
                            register: register.clone(),
                            definition: *definition,
                            use_at: instruction.address,
                        });
                    }
                } else {
                    live_in.insert(register.clone());
                }
            }
            for register in &instruction.effects.defs {
                reaching.insert(register.clone(), instruction.address);
            }
        }
        blocks.push(Block {
            id,
            function: slice[0].function,
            start: slice[0].address,
            end: slice.last().unwrap().address,
            instruction_count: slice.len(),
            normalized_sha256: digest(block_normalized.join("\n").as_bytes()),
            literal_sha256: digest(block_literals.join("\n").as_bytes()),
            terminator: slice.last().unwrap().flow.label(),
            unknown_effects: block_unknown,
            definitions,
            uses,
            live_in_candidates: live_in,
        });
        normalized.extend(block_normalized);
        literals.extend(block_literals);
    }
    let mut edges = Vec::new();
    for id in 0..starts.len() {
        let end = starts
            .get(id + 1)
            .copied()
            .unwrap_or(parsed.instructions.len());
        let last = &parsed.instructions[end - 1];
        if matches!(last.flow, Flow::Conditional | Flow::Jump | Flow::Call) {
            let target = targets
                .get(&(end - 1))
                .copied()
                .filter(|target| *target < instruction_blocks.len());
            let target_scope = if let Some(target) = target {
                if parsed.instructions[target].function == last.function {
                    "same_function"
                } else {
                    "other_function"
                }
            } else if last.target.is_some() {
                "unresolved_or_outside_parsed_range"
            } else {
                "indirect_or_symbolic"
            };
            edges.push(Edge {
                from_block: id,
                from: last.address,
                to: last.target,
                to_block: target.map(|index| instruction_blocks[index]),
                kind: last.flow.label(),
                target_scope,
            });
        }
        if last.flow.falls_through()
            && end < parsed.instructions.len()
            && consecutive(last, &parsed.instructions[end])
        {
            edges.push(Edge {
                from_block: id,
                from: last.address,
                to: Some(parsed.instructions[end].address),
                to_block: Some(instruction_blocks[end]),
                kind: "fallthrough",
                target_scope: "same_function",
            });
        }
    }
    let mut shapes = BTreeMap::<(&str, &str, usize), usize>::new();
    for block in &blocks {
        *shapes
            .entry((
                &block.normalized_sha256,
                block.terminator,
                block.instruction_count,
            ))
            .or_default() += 1;
    }
    let shape_rows=shapes.into_iter().map(|((sha256,terminator,instructions),count)|json!({"sha256":sha256,"terminator":terminator,"instructions":instructions,"count":count})).collect::<Vec<_>>();
    let cfg = edges
        .iter()
        .map(|edge| (edge.from_block, edge.to_block, edge.kind))
        .collect::<Vec<_>>();
    let architecture = BTreeSet::from_iter(
        parsed
            .instructions
            .iter()
            .filter(|instruction| instruction.architecture != Architecture::Unknown)
            .map(|instruction| instruction.architecture.label()),
    );
    let architecture = if architecture.len() == 1 {
        architecture.first().copied().unwrap()
    } else if architecture.is_empty() {
        "unknown"
    } else {
        "mixed"
    };
    json!({"schema":"fileveil.binary-forensics.v1","architecture":architecture,"instruction_count":parsed.instructions.len(),"function_count":parsed.functions,
        "basic_block_count":blocks.len(),"basic_blocks":blocks.iter().take(MAX_BLOCK_DETAILS).collect::<Vec<_>>(),"block_fingerprints":shape_rows,
        "cfg_edge_count":edges.len(),"cfg_edges":edges.iter().take(MAX_DETAILS).collect::<Vec<_>>(),"cfg_shape_sha256":digest(&serde_json::to_vec(&cfg).unwrap_or_default()),
        "normalized_instruction_sha256":digest(normalized.join("\n").as_bytes()),"operand_literal_sha256":digest(literals.join("\n").as_bytes()),
        "def_use_link_count":link_count,"def_use_candidates":links,"unknown_effect_instructions":unknown,"unmodeled_opcodes":unknown_opcodes,
        "truncated":parsed.truncated,"malformed_instruction_lines":parsed.malformed,"details_limited":blocks.len()>MAX_BLOCK_DETAILS || edges.len()>MAX_DETAILS || link_count>MAX_DETAILS,
        "scope":"heuristic_basic_blocks_direct_control_flow_and_block_local_register_def_use",
        "register_alias_scope":"register_families_with_conservative_partial_gpr_writes","memory_alias_analysis":"not_assessed","cross_block_dataflow":"not_assessed",
        "semantic_equivalence":"not_assessed","unknown_watermark_detection":"not_assessed","protocol_signature_authority":"separate_authenticated_packet_verifier"})
}

fn fingerprints(report: &Value) -> BTreeMap<String, u64> {
    report["block_fingerprints"]
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_BLOCKS)
        .filter_map(|row| {
            Some((
                row["sha256"].as_str()?.to_owned(),
                row["count"].as_u64()?.min(MAX_BLOCKS as u64),
            ))
        })
        .collect()
}
/// Compare syntactic evidence. These similarities do not imply equivalent behavior.
pub(super) fn compare(before: &Value, after: &Value) -> Value {
    if before["schema"] != "fileveil.binary-forensics.v1"
        || after["schema"] != "fileveil.binary-forensics.v1"
    {
        return json!({"status":"not_assessed","scope":"requires_binary_forensics_v1_reports"});
    }
    if before["instruction_count"].as_u64().unwrap_or(0) == 0
        || after["instruction_count"].as_u64().unwrap_or(0) == 0
    {
        return json!({"status":"not_assessed","scope":"no_parsed_instructions_in_one_or_both_inputs","semantic_equivalence":"not_assessed","watermark_attribution":"not_assessed"});
    }
    let left = fingerprints(before);
    let right = fingerprints(after);
    let matched = left
        .iter()
        .map(|(hash, count)| (*count).min(right.get(hash).copied().unwrap_or(0)))
        .sum::<u64>();
    let left_count = left
        .values()
        .fold(0u64, |total, count| total.saturating_add(*count));
    let right_count = right
        .values()
        .fold(0u64, |total, count| total.saturating_add(*count));
    let removed = left
        .iter()
        .map(|(hash, count)| {
            (
                hash,
                count.saturating_sub(right.get(hash).copied().unwrap_or(0)),
            )
        })
        .filter(|(_, count)| *count > 0)
        .take(64)
        .map(|(hash, count)| json!({"sha256":hash,"count":count}))
        .collect::<Vec<_>>();
    let added = right
        .iter()
        .map(|(hash, count)| {
            (
                hash,
                count.saturating_sub(left.get(hash).copied().unwrap_or(0)),
            )
        })
        .filter(|(_, count)| *count > 0)
        .take(64)
        .map(|(hash, count)| json!({"sha256":hash,"count":count}))
        .collect::<Vec<_>>();
    json!({"schema":"fileveil.binary-forensics-comparison.v1","status":"analyzed","scope":"heuristic_structural_difference_candidates",
        "same_architecture":before["architecture"]==after["architecture"],"before_instructions":before["instruction_count"],"after_instructions":after["instruction_count"],
        "before_blocks":left_count,"after_blocks":right_count,"matched_block_fingerprints":matched,"before_unmatched_blocks":left_count.saturating_sub(matched),"after_unmatched_blocks":right_count.saturating_sub(matched),
        "block_dice_similarity":if left_count+right_count>0{Some(2.0*matched as f64/(left_count+right_count) as f64)}else{None},
        "same_normalized_instructions":before["normalized_instruction_sha256"]==after["normalized_instruction_sha256"],"same_cfg_shape":before["cfg_shape_sha256"]==after["cfg_shape_sha256"],
        "operand_literal_change_candidates":before["operand_literal_sha256"]!=after["operand_literal_sha256"],"removed_block_candidates":removed,"added_block_candidates":added,
        "partial_coverage":before["truncated"]==true || after["truncated"]==true || before["malformed_instruction_lines"].as_u64().unwrap_or(0)>0 || after["malformed_instruction_lines"].as_u64().unwrap_or(0)>0,
        "unknown_effects_before":before["unknown_effect_instructions"],"unknown_effects_after":after["unknown_effect_instructions"],
        "dataflow_partial":before["unknown_effect_instructions"].as_u64().unwrap_or(0)>0 || after["unknown_effect_instructions"].as_u64().unwrap_or(0)>0,
        "semantic_equivalence":"not_assessed","watermark_attribution":"not_assessed"})
}

const MAX_CLUE_SAMPLE: usize = 2 * 1024 * 1024;
fn word(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn rich_records(bytes: &[u8]) -> Option<usize> {
    if bytes.get(..2) != Some(b"MZ".as_slice()) {
        return None;
    }
    let pe = word(bytes, 0x3c)? as usize;
    if pe > MAX_CLUE_SAMPLE || bytes.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let end = pe.min(65536);
    let mut candidates = 0usize;
    for rich in (0x50..end.saturating_sub(7))
        .rev()
        .filter(|offset| offset.is_multiple_of(4))
    {
        if bytes.get(rich..rich + 4) != Some(b"Rich".as_slice()) {
            continue;
        }
        candidates += 1;
        if candidates > 16 {
            return None;
        }
        let key = word(bytes, rich + 4)?;
        for start in (0x40..rich.saturating_sub(15))
            .rev()
            .filter(|offset| offset.is_multiple_of(4))
        {
            if word(bytes, start)? ^ key != 0x536e6144 {
                continue;
            }
            let size = rich.checked_sub(start + 16)?;
            if size == 0 || !size.is_multiple_of(8) || size / 8 > 4096 {
                continue;
            }
            if (1..=3)
                .all(|index| word(bytes, start + index * 4).is_some_and(|value| value ^ key == 0))
            {
                return Some(size / 8);
            }
        }
    }
    None
}
/// Compiler markers are build clues. Producer text and private values are omitted.
pub(super) fn compiler_clues(bytes: &[u8]) -> Value {
    let first = bytes.len().min(MAX_CLUE_SAMPLE);
    let mut sampled_bytes = first;
    let mut sample = bytes[..first].to_ascii_lowercase();
    if bytes.len() > first {
        let start = first.max(bytes.len().saturating_sub(MAX_CLUE_SAMPLE));
        sampled_bytes += bytes.len() - start;
        sample.push(0);
        sample.extend(bytes[start..].iter().map(u8::to_ascii_lowercase));
    }
    let contains = |needle: &[u8]| sample.windows(needle.len()).any(|window| window == needle);
    let clang = contains(b"clang version");
    let gcc = contains(b"gcc: (") || contains(b"gcc version");
    let rustc = contains(b"rustc version") || contains(b"rustc/");
    let rich = rich_records(bytes);
    let mut candidates = Vec::new();
    if clang {
        candidates.push("clang_family")
    }
    if gcc {
        candidates.push("gcc_family")
    }
    if rustc {
        candidates.push("rustc_family")
    }
    if rich.is_some() {
        candidates.push("msvc_toolchain_rich_structure")
    }
    json!({"schema":"fileveil.compiler-clues.v1","candidates":candidates,"sampled_bytes":sampled_bytes,"sample_scope":"bounded_first_and_last_2_mib",
        "sampling_truncated":bytes.len()>MAX_CLUE_SAMPLE*2,"pe_rich_record_count":rich,"rich_checksum":"not_assessed","rich_scope":"first_64_kib_maximum_16_candidate_headers",
        "scope":"unauthenticated_build_marker_candidates","compiler_identity":"not_assessed","watermark_evidence":false,"raw_producer_strings_exported":false})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arm64_blocks_flags_and_register_aliases_have_reproducible_local_links() {
        let text = "sample: file format mach-o arm64\n0000000000001000 <private_function_name>:\n1000: d2800540 mov x0, #42\n1004: add w1, w0, #1\n1008: cmp w1, #2\n100c: b.eq 0x1018 <private_function_name+0x18>\n1010: sub w2, w1, #1\n1014: b 0x101c\n1018: mov w2, w1\n101c: ret\n";
        let report = analyze(text);
        assert_eq!(report["instruction_count"], 8);
        assert_eq!(report["basic_block_count"], 4);
        assert_eq!(report["cfg_edge_count"], 4);
        assert_eq!(report["architecture"], "aarch64");
        assert!(report["def_use_link_count"].as_u64().unwrap() >= 3);
        assert!(report["def_use_candidates"].as_array().unwrap().iter().any(
            |link| link["register"] == "x0"
                && link["definition"] == 0x1000
                && link["use_at"] == 0x1004
        ));
        assert!(!report.to_string().contains("private_function_name"));
        assert_eq!(report["unknown_watermark_detection"], "not_assessed");
    }
    #[test]
    fn x86_att_raw_bytes_comments_and_conditional_edges_are_analyzed() {
        let text = "sample: file format elf64-x86-64\n0000000000001000 <main>:\n1000: 89 f8 movl %edi, %eax\n1002: 83 c0 05 addl $5, %eax\n1005: 85 c0 testl %eax, %eax # 0x2000 <rax>\n1007: 74 07 je 0x1010\n1009: c3 retq\n1010: c3 retq\n";
        let report = analyze(text);
        assert_eq!(report["instruction_count"], 6);
        assert_eq!(report["basic_block_count"], 3);
        assert_eq!(report["architecture"], "x86_64");
        assert!(report["def_use_link_count"].as_u64().unwrap() >= 3);
        assert_eq!(report["unknown_effect_instructions"], 0);
    }
    #[test]
    fn unknown_effects_and_calls_stop_reaching_definition_claims() {
        let report = analyze(
            "1000: mov x0, #1\n1004: vendor_unknown x0, x1\n1008: add x2, x0, #1\n100c: bl 0x2000\n1010: add x3, x2, #1\n1014: ret\n",
        );
        assert_eq!(report["unknown_effect_instructions"], 2);
        assert!(
            !report["def_use_candidates"]
                .as_array()
                .unwrap()
                .iter()
                .any(|link| link["definition"] == 0x1000 && link["use_at"] == 0x1008)
        );
        assert!(
            !report["def_use_candidates"]
                .as_array()
                .unwrap()
                .iter()
                .any(|link| link["definition"] == 0x1008 && link["use_at"] == 0x1010)
        );
    }
    #[test]
    fn normalized_structure_survives_register_renaming_and_reports_literal_changes() {
        let before = analyze("1000: mov x0, #42\n1004: add x1, x0, #3\n1008: ret\n");
        let after = analyze("2000: mov x8, #99\n2004: add x9, x8, #3\n2008: ret\n");
        let compared = compare(&before, &after);
        assert_eq!(compared["same_normalized_instructions"], true);
        assert_eq!(compared["same_cfg_shape"], true);
        assert_eq!(compared["operand_literal_change_candidates"], true);
        assert_eq!(compared["semantic_equivalence"], "not_assessed");
        let different =
            analyze("1000: mov x0, #42\n1004: cbz x0, 0x100c\n1008: add x1, x0, #3\n100c: ret\n");
        assert_eq!(compare(&before, &different)["same_cfg_shape"], false);
    }
    #[test]
    fn negative_empty_malformed_and_duplicate_address_samples_fail_safely() {
        let empty = analyze("not an objdump file\n");
        assert_eq!(empty["instruction_count"], 0);
        let malformed = analyze("1000: mov x0, [x1\n1004: !!!\n1008: mov x0, #1\n1008: b 0x1008\n");
        assert_eq!(malformed["malformed_instruction_lines"], 2);
        assert_eq!(malformed["cfg_edges"][0]["to_block"], Value::Null);
        assert_eq!(compare(&json!({}), &empty)["status"], "not_assessed");
    }
    #[test]
    fn large_and_unicode_text_obey_analysis_and_output_budgets() {
        let mut text = String::new();
        for index in 0..MAX_BLOCKS + 20 {
            text.push_str(&format!("{:x}: retq\n", 0x1000 + index));
        }
        text.push_str(&"界".repeat(MAX_TEXT / 3 + 10));
        let report = analyze(&text);
        assert_eq!(report["truncated"], true);
        assert!(report["basic_block_count"].as_u64().unwrap() <= MAX_BLOCKS as u64);
        assert!(report["basic_blocks"].as_array().unwrap().len() <= MAX_BLOCK_DETAILS);
    }
    #[test]
    fn compiler_clues_require_rich_structure_and_never_export_producer_values() {
        let report = compiler_clues(
            b"GCC: (GNU) 99.77 private-producer-name\0Homebrew clang version 23\0Rich",
        );
        assert_eq!(report["candidates"], json!(["clang_family", "gcc_family"]));
        assert_eq!(report["pe_rich_record_count"], Value::Null);
        assert!(!report.to_string().contains("private-producer-name"));
        assert_eq!(report["watermark_evidence"], false);
        let mut pe = vec![0u8; 0x104];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x100u32.to_le_bytes());
        pe[0x100..].copy_from_slice(b"PE\0\0");
        let key = 0x12345678u32;
        for (index, value) in [0x536e6144u32, 0, 0, 0, 0x10001, 7].into_iter().enumerate() {
            pe[0x40 + index * 4..0x44 + index * 4].copy_from_slice(&(value ^ key).to_le_bytes());
        }
        pe[0x58..0x5c].copy_from_slice(b"Rich");
        pe[0x5c..0x60].copy_from_slice(&key.to_le_bytes());
        assert_eq!(compiler_clues(&pe)["pe_rich_record_count"], 1);
    }
}

// FVPROV1 47485 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI3YTFmNDEwMDZlYWJiOTk4ZjY1OTNkYWUwZTEzZTE2ODBkNmRkNmZmMDAzZGUwZDRlNmViMjYyYzI2OGJkM2MyIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3NvZnR3YXJlL2ZvcmVuc2ljcy5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6Ijg0Mzc2M2IyOWVlNTZiZGQ3OWZmZjNiMDE1MTVhYzQ3YWI3NTE4ZGQ5MzkzZTJiYjViMDA0ZTQ1YmJlMjMxNzhlYTg3ZjUzOTk3MzFiYmQzYTIyNmI1Y2M4NTNhYzUwNzIwNTNiZTk0YjlkZGNhZWNmOTViNWJmODdkY2NhMTBmIn1dfV0= FVPROV1-END
