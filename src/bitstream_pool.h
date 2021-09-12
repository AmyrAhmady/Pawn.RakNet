/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016-2021 katursis
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

#ifndef PAWNRAKNET_BITSTREAM_POOL_H_
#define PAWNRAKNET_BITSTREAM_POOL_H_

class BitStreamPool {
 public:
  BitStream *New() {
    for (auto &[bs, is_occupied] : items_) {
      if (!is_occupied) {
        is_occupied = true;

        return bs.get();
      }
    }

    const auto &[bs, is_occupied] =
        items_.emplace_back(std::make_shared<BitStream>(), true);

    return bs.get();
  }

  void Delete(BitStream *ptr) {
    for (auto &[bs, is_occupied] : items_) {
      if (bs.get() == ptr) {
        bs->Reset();

        is_occupied = false;

        return;
      }
    }
  }

 private:
  using Item =
      std::pair<std::shared_ptr<BitStream> /* bs */, bool /* is_occupied */>;

  std::vector<Item> items_;
};

#endif  // PAWNRAKNET_BITSTREAM_POOL_H_