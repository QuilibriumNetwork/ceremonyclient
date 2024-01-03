/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bls48581

// Pairing Friendly?
const NOT int = 0
const BN int = 1
const BLS12 int = 2
const BLS24 int = 3
const BLS48 int = 4

// Sparsity
const FP_ZERO int = 0
const FP_ONE int = 1
const FP_SPARSEST int = 2
const FP_SPARSER int = 3
const FP_SPARSE int = 4
const FP_DENSE int = 5

const CURVE_A int = 0

const ATE_BITS int = 33
const G2_TABLE int = 36
const HTC_ISO int = 0
const HTC_ISO_G2 int = 0

const HASH_TYPE int = 64
const AESKEY int = 32

const USE_GLV bool = true
const USE_GS_G2 bool = true
const USE_GS_GT bool = true
