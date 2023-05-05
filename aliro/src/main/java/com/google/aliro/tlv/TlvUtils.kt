/*
 * Copyright 2023 Google LLC
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

package com.google.aliro.tlv

import com.payneteasy.tlv.BerTag
import com.payneteasy.tlv.BerTlv
import com.payneteasy.tlv.BerTlvs

fun BerTlvs.requireTag(tag: Int): BerTlv {
  return find(BerTag(tag))
    ?: throw IllegalArgumentException("Missing required tag 0x${Integer.toHexString(tag)}")
}

fun BerTlv.requireTag(tag: Int): BerTlv {
  return find(BerTag(tag))
    ?: throw IllegalArgumentException("Missing required tag 0x${Integer.toHexString(tag)}")
}

fun BerTlvs.optionalTag(tag: Int): BerTlv? = find(BerTag(tag))
fun BerTlv.optionalTag(tag: Int): BerTlv? = find(BerTag(tag))
