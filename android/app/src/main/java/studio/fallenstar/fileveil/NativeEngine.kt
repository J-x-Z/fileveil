// SPDX-License-Identifier: MPL-2.0
package studio.fallenstar.fileveil

object NativeEngine {
    init { System.loadLibrary("fileveil_jni") }
    external fun request(root: ByteArray, request: ByteArray, seed: ByteArray?): ByteArray
}

