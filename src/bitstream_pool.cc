/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016-2023 katursis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "main.h"

BitStreamPool BitStreamPool::Instance;

uint32_t BitStreamPool::FindFreePoolID() const {
  static uint32_t last_used_id = -1;

  last_used_id++;

  if (last_used_id == MAX_BS_POOL_NUMBER) {
    // let's reset id back to -1
    last_used_id = -1;
    return FindFreePoolID();
  }

  if (items_.find(last_used_id) == items_.end()) {
    return last_used_id;
  } else {
    return FindFreePoolID();
  }
}

std::pair<uint32_t, std::shared_ptr<BitStream>> BitStreamPool::New() {
  uint32_t id = FindFreePoolID();
  auto bs = std::make_shared<BitStream>();
  auto pair = items_.insert({ id, bs });

  return { id, bs };
}

std::pair<uint32_t, std::shared_ptr<BitStream>> BitStreamPool::New(BitStream* bs) {
  uint32_t id = FindFreePoolID();
  auto shadow = std::make_shared<BitStream>(bs->GetData(), bs->GetNumberOfBytesUsed(), false);
  auto pair = items_.insert({ id, shadow });

  return { id, shadow };
}

void BitStreamPool::Delete(uint32_t id) {
  auto it = items_.find(id);
  if (it != items_.end()) {
    it->second.reset();
    items_.erase(it);
  }
}

BitStream *BitStreamPool::GetBSFromID(uint32_t id) {
  auto it = items_.find(id);
  if (it != items_.end()) {
    return it->second.get();
  } else {
    return nullptr;
  }
}
