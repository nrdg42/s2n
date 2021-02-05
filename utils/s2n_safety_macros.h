
/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#pragma once

/**
 * DO NOT DIRECTLY MODIFY THIS FILE:
 *
 * The code in this file is generated from scripts/s2n_safety_macros.py and any modifications
 * should be in there.
 */

#include "error/s2n_errno.h"
#include "utils/s2n_ensure.h"
#include "utils/s2n_result.h"

/**
 * The goal of s2n_safety is to provide helpers to perform common
 * checks, which help with code readability.
 */

/* Success signal value for OpenSSL functions */
#define _OSSL_SUCCESS 1

/**
 * Sets the global `s2n_errno` to `error` and returns with an `S2N_RESULT_ERROR`
 */
#define RESULT_BAIL(error)                                     do { _S2N_ERROR((error)); return S2N_RESULT_ERROR; } while (0)

/**
 * Ensures the `condition` is `true`, otherwise the function will `RESULT_BAIL` with `error`
 */
#define RESULT_ENSURE(condition, error)                        __S2N_ENSURE((condition), RESULT_BAIL(error))

/**
 * Ensures `s2n_result_is_ok(result)`, otherwise the function will `RESULT_BAIL` with `error`
 *
 * This can be useful for overriding the global `s2n_errno`
 */
#define RESULT_ENSURE_OK(result, error)                        __S2N_ENSURE(s2n_result_is_ok(result), RESULT_BAIL(error))

/**
 * Ensures `a` is greater than or equal to `b`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define RESULT_ENSURE_GTE(a, b)                                __S2N_ENSURE((a) >= (b), RESULT_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is less than or equal to `b`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define RESULT_ENSURE_LTE(a, b)                                __S2N_ENSURE((a) <= (b), RESULT_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is greater than `b`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define RESULT_ENSURE_GT(a, b)                                 __S2N_ENSURE((a) > (b), RESULT_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is less than `b`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define RESULT_ENSURE_LT(a, b)                                 __S2N_ENSURE((a) < (b), RESULT_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is equal to `b`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define RESULT_ENSURE_EQ(a, b)                                 __S2N_ENSURE((a) == (b), RESULT_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is not equal to `b`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define RESULT_ENSURE_NE(a, b)                                 __S2N_ENSURE((a) != (b), RESULT_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `min <= n <= max`, otherwise the function will `RESULT_BAIL` with `S2N_ERR_SAFETY`
 */
#define RESULT_ENSURE_INCLUSIVE_RANGE(min, n, max)              \
        do { \
            __typeof(n) __tmp_n = ( n ); \
            __typeof(n) __tmp_min = ( min ); \
            __typeof(n) __tmp_max = ( max ); \
            RESULT_ENSURE_GTE(__tmp_n, __tmp_min); \
            RESULT_ENSURE_LTE(__tmp_n, __tmp_max); \
        } while(0)

/**
 * Ensures `min < n < max`, otherwise the function will `RESULT_BAIL` with `S2N_ERR_SAFETY`
 */
#define RESULT_ENSURE_EXCLUSIVE_RANGE(min, n, max)              \
        do { \
            __typeof(n) __tmp_n = ( n ); \
            __typeof(n) __tmp_min = ( min ); \
            __typeof(n) __tmp_max = ( max ); \
            RESULT_ENSURE_GT(__tmp_n, __tmp_min); \
            RESULT_ENSURE_LT(__tmp_n, __tmp_max); \
        } while(0)

/**
 * Ensures `x` is a readable reference, otherwise the function will `RESULT_BAIL` with `S2N_ERR_NULL`
 */
#define RESULT_ENSURE_REF(x)                                   __S2N_ENSURE(S2N_OBJECT_PTR_IS_READABLE(x), RESULT_BAIL(S2N_ERR_NULL))

/**
 * Ensures `x` is a mutable reference, otherwise the function will `RESULT_BAIL` with `S2N_ERR_NULL`
 */
#define RESULT_ENSURE_MUT(x)                                   __S2N_ENSURE(S2N_OBJECT_PTR_IS_WRITABLE(x), RESULT_BAIL(S2N_ERR_NULL))

/**
 * Ensures the `condition` is `true`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_PRECONDITION_VIOLATION` error
 */
#define RESULT_PRECONDITION(condition)                         __S2N_ENSURE_CONDITION((condition), RESULT_BAIL(S2N_ERR_PRECONDITION_VIOLATION))

/**
 * Ensures the `condition` is `true`, otherwise the function will `RESULT_BAIL` with a `S2N_ERR_POSTCONDITION_VIOLATION` error
 */
#define RESULT_POSTCONDITION(condition)                        __S2N_ENSURE_CONDITION((condition), RESULT_BAIL(S2N_ERR_POSTCONDITION_VIOLATION))

/**
 * Performs a safer memcpy.
 *
 * The following checks are performed:
 *
 * * `destination` is non-null
 * * `source` is non-null
 *
 * Callers will still need to ensure the following:
 *
 * * The size of the data pointed to by both the `destination` and `source` parameters,
 *   shall be at least `len` bytes.
 */
#define RESULT_CHECKED_MEMCPY(destination, source, len)        __S2N_ENSURE_SAFE_MEMCPY((destination), (source), (len), RESULT_GUARD_PTR)

/**
 * Performs a safer memset
 *
 * The following checks are performed:
 *
 * * `destination` is non-null
 *
 * Callers will still need to ensure the following:
 *
 * * The size of the data pointed to by the `destination` parameter shall be at least
 *   `len` bytes.
 */
#define RESULT_CHECKED_MEMSET(destination, value, len)         __S2N_ENSURE_SAFE_MEMSET((destination), (value), (len), RESULT_ENSURE_REF)

/**
 * Ensures `s2n_result_is_ok(result)`, otherwise the function will return `S2N_RESULT_ERROR`
 */
#define RESULT_GUARD(result)                                   __S2N_ENSURE(s2n_result_is_ok(result), return S2N_RESULT_ERROR)

/**
 * Ensures `result == _OSSL_SUCCESS`, otherwise the function will `RESULT_BAIL` with `error`
 */
#define RESULT_GUARD_OSSL(result, error)                       __S2N_ENSURE((result) == _OSSL_SUCCESS, RESULT_BAIL(error))

/**
 * Ensures `s2n_result_is_ok(result)`, otherwise the function will return `S2N_RESULT_ERROR`
 */
#define RESULT_GUARD_RESULT(result)                            __S2N_ENSURE(s2n_result_is_ok(result), return S2N_RESULT_ERROR)

/**
 * Ensures `(result) >= S2N_SUCCESS`, otherwise the function will return `S2N_RESULT_ERROR`
 */
#define RESULT_GUARD_POSIX(result)                             __S2N_ENSURE((result) >= S2N_SUCCESS, return S2N_RESULT_ERROR)

/**
 * Ensures `(result) != NULL`, otherwise the function will return `S2N_RESULT_ERROR`
 */
#define RESULT_GUARD_PTR(result)                               __S2N_ENSURE((result) != NULL, return S2N_RESULT_ERROR)

/**
 * Sets the global `s2n_errno` to `error` and returns with an `S2N_FAILURE`
 */
#define POSIX_BAIL(error)                                     do { _S2N_ERROR((error)); return S2N_FAILURE; } while (0)

/**
 * Ensures the `condition` is `true`, otherwise the function will `POSIX_BAIL` with `error`
 */
#define POSIX_ENSURE(condition, error)                        __S2N_ENSURE((condition), POSIX_BAIL(error))

/**
 * Ensures `(result) >= S2N_SUCCESS`, otherwise the function will `POSIX_BAIL` with `error`
 *
 * This can be useful for overriding the global `s2n_errno`
 */
#define POSIX_ENSURE_OK(result, error)                        __S2N_ENSURE((result) >= S2N_SUCCESS, POSIX_BAIL(error))

/**
 * Ensures `a` is greater than or equal to `b`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define POSIX_ENSURE_GTE(a, b)                                __S2N_ENSURE((a) >= (b), POSIX_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is less than or equal to `b`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define POSIX_ENSURE_LTE(a, b)                                __S2N_ENSURE((a) <= (b), POSIX_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is greater than `b`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define POSIX_ENSURE_GT(a, b)                                 __S2N_ENSURE((a) > (b), POSIX_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is less than `b`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define POSIX_ENSURE_LT(a, b)                                 __S2N_ENSURE((a) < (b), POSIX_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is equal to `b`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define POSIX_ENSURE_EQ(a, b)                                 __S2N_ENSURE((a) == (b), POSIX_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is not equal to `b`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define POSIX_ENSURE_NE(a, b)                                 __S2N_ENSURE((a) != (b), POSIX_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `min <= n <= max`, otherwise the function will `POSIX_BAIL` with `S2N_ERR_SAFETY`
 */
#define POSIX_ENSURE_INCLUSIVE_RANGE(min, n, max)              \
        do { \
            __typeof(n) __tmp_n = ( n ); \
            __typeof(n) __tmp_min = ( min ); \
            __typeof(n) __tmp_max = ( max ); \
            POSIX_ENSURE_GTE(__tmp_n, __tmp_min); \
            POSIX_ENSURE_LTE(__tmp_n, __tmp_max); \
        } while(0)

/**
 * Ensures `min < n < max`, otherwise the function will `POSIX_BAIL` with `S2N_ERR_SAFETY`
 */
#define POSIX_ENSURE_EXCLUSIVE_RANGE(min, n, max)              \
        do { \
            __typeof(n) __tmp_n = ( n ); \
            __typeof(n) __tmp_min = ( min ); \
            __typeof(n) __tmp_max = ( max ); \
            POSIX_ENSURE_GT(__tmp_n, __tmp_min); \
            POSIX_ENSURE_LT(__tmp_n, __tmp_max); \
        } while(0)

/**
 * Ensures `x` is a readable reference, otherwise the function will `POSIX_BAIL` with `S2N_ERR_NULL`
 */
#define POSIX_ENSURE_REF(x)                                   __S2N_ENSURE(S2N_OBJECT_PTR_IS_READABLE(x), POSIX_BAIL(S2N_ERR_NULL))

/**
 * Ensures `x` is a mutable reference, otherwise the function will `POSIX_BAIL` with `S2N_ERR_NULL`
 */
#define POSIX_ENSURE_MUT(x)                                   __S2N_ENSURE(S2N_OBJECT_PTR_IS_WRITABLE(x), POSIX_BAIL(S2N_ERR_NULL))

/**
 * Ensures the `condition` is `true`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_PRECONDITION_VIOLATION` error
 */
#define POSIX_PRECONDITION(condition)                         __S2N_ENSURE_CONDITION((condition), POSIX_BAIL(S2N_ERR_PRECONDITION_VIOLATION))

/**
 * Ensures the `condition` is `true`, otherwise the function will `POSIX_BAIL` with a `S2N_ERR_POSTCONDITION_VIOLATION` error
 */
#define POSIX_POSTCONDITION(condition)                        __S2N_ENSURE_CONDITION((condition), POSIX_BAIL(S2N_ERR_POSTCONDITION_VIOLATION))

/**
 * Performs a safer memcpy.
 *
 * The following checks are performed:
 *
 * * `destination` is non-null
 * * `source` is non-null
 *
 * Callers will still need to ensure the following:
 *
 * * The size of the data pointed to by both the `destination` and `source` parameters,
 *   shall be at least `len` bytes.
 */
#define POSIX_CHECKED_MEMCPY(destination, source, len)        __S2N_ENSURE_SAFE_MEMCPY((destination), (source), (len), POSIX_GUARD_PTR)

/**
 * Performs a safer memset
 *
 * The following checks are performed:
 *
 * * `destination` is non-null
 *
 * Callers will still need to ensure the following:
 *
 * * The size of the data pointed to by the `destination` parameter shall be at least
 *   `len` bytes.
 */
#define POSIX_CHECKED_MEMSET(destination, value, len)         __S2N_ENSURE_SAFE_MEMSET((destination), (value), (len), POSIX_ENSURE_REF)

/**
 * Ensures `(result) >= S2N_SUCCESS`, otherwise the function will return `S2N_FAILURE`
 */
#define POSIX_GUARD(result)                                   __S2N_ENSURE((result) >= S2N_SUCCESS, return S2N_FAILURE)

/**
 * Ensures `result == _OSSL_SUCCESS`, otherwise the function will `POSIX_BAIL` with `error`
 */
#define POSIX_GUARD_OSSL(result, error)                       __S2N_ENSURE((result) == _OSSL_SUCCESS, POSIX_BAIL(error))

/**
 * Ensures `s2n_result_is_ok(result)`, otherwise the function will return `S2N_FAILURE`
 */
#define POSIX_GUARD_RESULT(result)                            __S2N_ENSURE(s2n_result_is_ok(result), return S2N_FAILURE)

/**
 * Ensures `(result) >= S2N_SUCCESS`, otherwise the function will return `S2N_FAILURE`
 */
#define POSIX_GUARD_POSIX(result)                             __S2N_ENSURE((result) >= S2N_SUCCESS, return S2N_FAILURE)

/**
 * Ensures `(result) != NULL`, otherwise the function will return `S2N_FAILURE`
 */
#define POSIX_GUARD_PTR(result)                               __S2N_ENSURE((result) != NULL, return S2N_FAILURE)

/**
 * Sets the global `s2n_errno` to `error` and returns with an `NULL`
 */
#define PTR_BAIL(error)                                       do { _S2N_ERROR((error)); return NULL; } while (0)

/**
 * Ensures the `condition` is `true`, otherwise the function will `PTR_BAIL` with `error`
 */
#define PTR_ENSURE(condition, error)                          __S2N_ENSURE((condition), PTR_BAIL(error))

/**
 * Ensures `(result) != NULL`, otherwise the function will `PTR_BAIL` with `error`
 *
 * This can be useful for overriding the global `s2n_errno`
 */
#define PTR_ENSURE_OK(result, error)                          __S2N_ENSURE((result) != NULL, PTR_BAIL(error))

/**
 * Ensures `a` is greater than or equal to `b`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define PTR_ENSURE_GTE(a, b)                                  __S2N_ENSURE((a) >= (b), PTR_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is less than or equal to `b`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define PTR_ENSURE_LTE(a, b)                                  __S2N_ENSURE((a) <= (b), PTR_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is greater than `b`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define PTR_ENSURE_GT(a, b)                                   __S2N_ENSURE((a) > (b), PTR_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is less than `b`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define PTR_ENSURE_LT(a, b)                                   __S2N_ENSURE((a) < (b), PTR_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is equal to `b`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define PTR_ENSURE_EQ(a, b)                                   __S2N_ENSURE((a) == (b), PTR_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `a` is not equal to `b`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_SAFETY` error
 */
#define PTR_ENSURE_NE(a, b)                                   __S2N_ENSURE((a) != (b), PTR_BAIL(S2N_ERR_SAFETY))

/**
 * Ensures `min <= n <= max`, otherwise the function will `PTR_BAIL` with `S2N_ERR_SAFETY`
 */
#define PTR_ENSURE_INCLUSIVE_RANGE(min, n, max)                \
        do { \
            __typeof(n) __tmp_n = ( n ); \
            __typeof(n) __tmp_min = ( min ); \
            __typeof(n) __tmp_max = ( max ); \
            PTR_ENSURE_GTE(__tmp_n, __tmp_min); \
            PTR_ENSURE_LTE(__tmp_n, __tmp_max); \
        } while(0)

/**
 * Ensures `min < n < max`, otherwise the function will `PTR_BAIL` with `S2N_ERR_SAFETY`
 */
#define PTR_ENSURE_EXCLUSIVE_RANGE(min, n, max)                \
        do { \
            __typeof(n) __tmp_n = ( n ); \
            __typeof(n) __tmp_min = ( min ); \
            __typeof(n) __tmp_max = ( max ); \
            PTR_ENSURE_GT(__tmp_n, __tmp_min); \
            PTR_ENSURE_LT(__tmp_n, __tmp_max); \
        } while(0)

/**
 * Ensures `x` is a readable reference, otherwise the function will `PTR_BAIL` with `S2N_ERR_NULL`
 */
#define PTR_ENSURE_REF(x)                                     __S2N_ENSURE(S2N_OBJECT_PTR_IS_READABLE(x), PTR_BAIL(S2N_ERR_NULL))

/**
 * Ensures `x` is a mutable reference, otherwise the function will `PTR_BAIL` with `S2N_ERR_NULL`
 */
#define PTR_ENSURE_MUT(x)                                     __S2N_ENSURE(S2N_OBJECT_PTR_IS_WRITABLE(x), PTR_BAIL(S2N_ERR_NULL))

/**
 * Ensures the `condition` is `true`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_PRECONDITION_VIOLATION` error
 */
#define PTR_PRECONDITION(condition)                           __S2N_ENSURE_CONDITION((condition), PTR_BAIL(S2N_ERR_PRECONDITION_VIOLATION))

/**
 * Ensures the `condition` is `true`, otherwise the function will `PTR_BAIL` with a `S2N_ERR_POSTCONDITION_VIOLATION` error
 */
#define PTR_POSTCONDITION(condition)                          __S2N_ENSURE_CONDITION((condition), PTR_BAIL(S2N_ERR_POSTCONDITION_VIOLATION))

/**
 * Performs a safer memcpy.
 *
 * The following checks are performed:
 *
 * * `destination` is non-null
 * * `source` is non-null
 *
 * Callers will still need to ensure the following:
 *
 * * The size of the data pointed to by both the `destination` and `source` parameters,
 *   shall be at least `len` bytes.
 */
#define PTR_CHECKED_MEMCPY(destination, source, len)          __S2N_ENSURE_SAFE_MEMCPY((destination), (source), (len), PTR_GUARD_PTR)

/**
 * Performs a safer memset
 *
 * The following checks are performed:
 *
 * * `destination` is non-null
 *
 * Callers will still need to ensure the following:
 *
 * * The size of the data pointed to by the `destination` parameter shall be at least
 *   `len` bytes.
 */
#define PTR_CHECKED_MEMSET(destination, value, len)           __S2N_ENSURE_SAFE_MEMSET((destination), (value), (len), PTR_ENSURE_REF)

/**
 * Ensures `(result) != NULL`, otherwise the function will return `NULL`
 */
#define PTR_GUARD(result)                                     __S2N_ENSURE((result) != NULL, return NULL)

/**
 * Ensures `result == _OSSL_SUCCESS`, otherwise the function will `PTR_BAIL` with `error`
 */
#define PTR_GUARD_OSSL(result, error)                         __S2N_ENSURE((result) == _OSSL_SUCCESS, PTR_BAIL(error))

/**
 * Ensures `s2n_result_is_ok(result)`, otherwise the function will return `NULL`
 */
#define PTR_GUARD_RESULT(result)                              __S2N_ENSURE(s2n_result_is_ok(result), return NULL)

/**
 * Ensures `(result) >= S2N_SUCCESS`, otherwise the function will return `NULL`
 */
#define PTR_GUARD_POSIX(result)                               __S2N_ENSURE((result) >= S2N_SUCCESS, return NULL)

/**
 * Ensures `(result) != NULL`, otherwise the function will return `NULL`
 */
#define PTR_GUARD_PTR(result)                                 __S2N_ENSURE((result) != NULL, return NULL)

