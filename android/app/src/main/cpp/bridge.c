// SPDX-License-Identifier: MPL-2.0
#include <jni.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
extern char *fileveil_android_call(const char *, const char *, const uint8_t *, size_t);
extern void fileveil_android_free(char *);
static char *copy_bytes(JNIEnv *env, jbyteArray data, jsize max) {
    if (!data) return NULL;
    jsize size = (*env)->GetArrayLength(env, data);
    if (size <= 0 || size > max) return NULL;
    char *result = calloc((size_t)size + 1, 1);
    if (!result) return NULL;
    (*env)->GetByteArrayRegion(env, data, 0, size, (jbyte *)result);
    if ((*env)->ExceptionCheck(env) || memchr(result, 0, (size_t)size)) { free(result); return NULL; }
    return result;
}
JNIEXPORT jbyteArray JNICALL Java_studio_fallenstar_fileveil_NativeEngine_request(JNIEnv *env, jobject self, jbyteArray path, jbyteArray request, jbyteArray key) {
    (void)self;
    char *root = copy_bytes(env, path, 4096), *json = copy_bytes(env, request, 16384);
    uint8_t seed[32] = {0};
    jsize key_size = key ? (*env)->GetArrayLength(env, key) : 0;
    char *response = NULL;
    if (root && json && (key_size == 0 || key_size == 32)) {
        if (key_size) (*env)->GetByteArrayRegion(env, key, 0, 32, (jbyte *)seed);
        if (!(*env)->ExceptionCheck(env)) response = fileveil_android_call(root, json, seed, (size_t)key_size);
    }
    volatile uint8_t *wipe = seed;
    for (size_t i = 0; i < sizeof(seed); ++i) wipe[i] = 0;
    free(root); free(json);
    const char *value = response ? response : "{\"ok\":false,\"error\":\"Invalid native request\"}";
    size_t length = strlen(value);
    jbyteArray output = (*env)->NewByteArray(env, (jsize)length);
    if (output) (*env)->SetByteArrayRegion(env, output, 0, (jsize)length, (const jbyte *)value);
    if (response) fileveil_android_free(response);
    return output;
}
