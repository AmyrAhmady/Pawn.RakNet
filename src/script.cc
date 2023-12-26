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

// native PR_Init();
cell Script::PR_Init() {
  InitHandlers();

  return 1;
}

// native PR_RegHandler(eventid, const publicname[], PR_EventType:type);
cell Script::PR_RegHandler(unsigned char event_id, std::string public_name,
                           PR_EventType type) {
  InitHandler(event_id, public_name, type);

  return 1;
}

// native PR_SendPacket(BitStream:bs, playerid, PR_PacketPriority:priority =
// PR_HIGH_PRIORITY, PR_PacketReliability:reliability = PR_RELIABLE_ORDERED,
// orderingchannel = 0);
cell Script::PR_SendPacket(cell id, int player_id,
                           PR_PacketPriority priority,
                           PR_PacketReliability reliability,
                           unsigned char ordering_channel) {
  GET_BS_CHECKED(id, bs);

  const bool broadcast = player_id == -1;

  auto core = PluginComponent::getCore();
  if (!core) {
    throw std::runtime_error{"Invalid component core"};
  }

  if (broadcast) {
    core->getPlayers().broadcastPacket(
        Span<uint8_t>(bs->GetData(), bs->GetNumberOfBitsUsed()),
        ordering_channel, nullptr, false);
  } else {
    auto player = core->getPlayers().get(player_id);
    if (!player) {
      throw std::runtime_error{"Invalid player"};
    }

    if (!player->sendPacket(
            Span<uint8_t>(bs->GetData(), bs->GetNumberOfBitsUsed()),
            ordering_channel, false)) {
      return 0;
    }
  }

  return 1;
}

// native PR_SendRPC(BitStream:bs, playerid, rpcid, PR_PacketPriority:priority
// = PR_HIGH_PRIORITY, PR_PacketReliability:reliability =
// PR_RELIABLE_ORDERED, orderingchannel = 0);
cell Script::PR_SendRPC(cell id, int player_id, RPCIndex rpc_id,
                        PR_PacketPriority priority,
                        PR_PacketReliability reliability,
                        unsigned char ordering_channel) {
  GET_BS_CHECKED(id, bs);

  const bool broadcast = player_id == -1;

  auto core = PluginComponent::getCore();
  if (!core) {
    throw std::runtime_error{"Invalid component core"};
  }

  if (broadcast) {
    core->getPlayers().broadcastRPC(
        rpc_id, Span<uint8_t>(bs->GetData(), bs->GetNumberOfBitsUsed()),
        ordering_channel, nullptr, false);
  } else {
    auto player = core->getPlayers().get(player_id);
    if (!player) {
      throw std::runtime_error{"Invalid player"};
    }

    if (!player->sendRPC(
            rpc_id, Span<uint8_t>(bs->GetData(), bs->GetNumberOfBitsUsed()),
            ordering_channel, false)) {
      return 0;
    }
  }

  return 1;
}

// native PR_EmulateIncomingPacket(BitStream:bs, playerid);
cell Script::PR_EmulateIncomingPacket(cell id, int player_id) {
  GET_BS_CHECKED(id, bs);

  auto core = PluginComponent::getCore();
  if (!core) {
    throw std::runtime_error{"Invalid component core"};
  }

  auto player = core->getPlayers().get(player_id);
  if (!player) {
    throw std::runtime_error{"Invalid player"};
  }

  auto data = bs->GetData();
  if (!data) {
    throw std::runtime_error{"Invalid bs data"};
  }

  int packet_id = static_cast<int>(data[0]);

  for (auto network : core->getNetworks()) {
    auto event_dispatcher =
        reinterpret_cast<Impl::DefaultEventDispatcher<NetworkInEventHandler> *>(
            &network->getInEventDispatcher());

    if (!event_dispatcher->stopAtFalse(
            [player, bs, packet_id](NetworkInEventHandler *handler) {
              if (handler == PluginComponent::get()) {
                return true;
              }

              bs->resetReadPointer();

              return handler->onReceivePacket(*player, packet_id, *bs);
            })) {
      return 1;
    }

    auto event_single_dispatcher = reinterpret_cast<
        Impl::DefaultIndexedEventDispatcher<SingleNetworkInEventHandler> *>(
        &network->getPerPacketInEventDispatcher());

    if (!event_single_dispatcher->stopAtFalse(
            packet_id, [player, bs](SingleNetworkInEventHandler *handler) {
              bs->resetReadPointer();

              return handler->onReceive(*player, *bs);
            })) {
      return 1;
    }
  }

  return 1;
}

// native PR_EmulateIncomingRPC(BitStream:bs, playerid, rpcid);
cell Script::PR_EmulateIncomingRPC(cell id, int player_id,
                                   RPCIndex rpc_id) {
  GET_BS_CHECKED(id, bs);

  auto core = PluginComponent::getCore();
  if (!core) {
    throw std::runtime_error{"Invalid component core"};
  }

  auto player = core->getPlayers().get(player_id);
  if (!player) {
    throw std::runtime_error{"Invalid player"};
  }

  for (auto network : core->getNetworks()) {
    auto event_dispatcher =
        reinterpret_cast<Impl::DefaultEventDispatcher<NetworkInEventHandler> *>(
            &network->getInEventDispatcher());

    if (!event_dispatcher->stopAtFalse(
            [player, bs, rpc_id](NetworkInEventHandler *handler) {
              if (handler == PluginComponent::get()) {
                return true;
              }

              bs->resetReadPointer();

              return handler->onReceiveRPC(*player, rpc_id, *bs);
            })) {
      return 1;
    }

    auto event_single_dispatcher = reinterpret_cast<
        Impl::DefaultIndexedEventDispatcher<SingleNetworkInEventHandler> *>(
        &network->getPerRPCInEventDispatcher());

    if (!event_single_dispatcher->stopAtFalse(
            rpc_id, [player, bs](SingleNetworkInEventHandler *handler) {
              bs->resetReadPointer();

              return handler->onReceive(*player, *bs);
            })) {
      return 1;
    }
  }

  return 1;
}

// native BitStream:BS_New();
cell Script::BS_New() { 
  auto item = BitStreamPool::Instance.New();
  return static_cast<cell>(item.first);
}

// native BitStream:BS_NewCopy(BitStream:bs);
cell Script::BS_NewCopy(cell id) {
  auto bs = BitStreamPool::Instance.GetBSFromID(id);

  if (bs) {
    const auto item_copy = BitStreamPool::Instance.New();

    int original_read_offset = bs->GetReadOffset();

    bs->resetReadPointer();

    item_copy.second->Write(bs);

    bs->SetReadOffset(original_read_offset);

    return static_cast<cell>(item_copy.first);
  }
  else {
    return MAX_BS_POOL_NUMBER;
  }
}

// native BS_Delete(BitStream:bs);
cell Script::BS_Delete(cell id) {
    BitStreamPool::Instance.Delete(static_cast<uint32_t>(id));
  return 1;
}

// native BS_Reset(BitStream:bs);
cell Script::BS_Reset(cell id) {
  GET_BS_CHECKED(id, bs);

  bs->reset();
  return 1;
}

// native BS_ResetReadPointer(BitStream:bs);
cell Script::BS_ResetReadPointer(cell id) {
  GET_BS_CHECKED(id, bs);

  bs->resetReadPointer();
  return 1;
}

// native BS_ResetWritePointer(BitStream:bs);
cell Script::BS_ResetWritePointer(cell id) {
  GET_BS_CHECKED(id, bs);

  bs->resetWritePointer();
  return 1;
}

// native BS_IgnoreBits(BitStream:bs, number_of_bits);
cell Script::BS_IgnoreBits(cell id, int number_of_bits) {
  GET_BS_CHECKED(id, bs);

  bs->IgnoreBits(number_of_bits);
  return 1;
}

// native BS_SetWriteOffset(BitStream:bs, offset);
cell Script::BS_SetWriteOffset(cell id, int offset) {
  GET_BS_CHECKED(id, bs);

  bs->SetWriteOffset(offset);
  return 1;
}

// native BS_GetWriteOffset(BitStream:bs, &offset);
cell Script::BS_GetWriteOffset(cell id, cell *offset) {
  GET_BS_CHECKED(id, bs);

  *offset = bs->GetWriteOffset();
  return 1;
}

// native BS_SetReadOffset(BitStream:bs, offset);
cell Script::BS_SetReadOffset(cell id, int offset) {
  GET_BS_CHECKED(id, bs);

  bs->SetReadOffset(offset);
  return 1;
}

// native BS_GetReadOffset(BitStream:bs, &offset);
cell Script::BS_GetReadOffset(cell id, cell *offset) {
  GET_BS_CHECKED(id, bs);

  *offset = bs->GetReadOffset();
  return 1;
}

// native BS_GetNumberOfBitsUsed(BitStream:bs, &number);
cell Script::BS_GetNumberOfBitsUsed(cell id, cell *number) {
  GET_BS_CHECKED(id, bs);

  *number = bs->GetNumberOfBitsUsed();
  return 1;
}

// native BS_GetNumberOfBytesUsed(BitStream:bs, &number);
cell Script::BS_GetNumberOfBytesUsed(cell id, cell *number) {
  GET_BS_CHECKED(id, bs);

  *number = bs->GetNumberOfBytesUsed();
  return 1;
}

// native BS_GetNumberOfUnreadBits(BitStream:bs, &number);
cell Script::BS_GetNumberOfUnreadBits(cell id, cell *number) {
  GET_BS_CHECKED(id, bs);

  *number = bs->GetNumberOfUnreadBits();
  return 1;
}

// native BS_GetNumberOfBitsAllocated(BitStream:bs, &number);
cell Script::BS_GetNumberOfBitsAllocated(cell id, cell *number) {
  GET_BS_CHECKED(id, bs);

  *number = bs->GetNumberOfBitsAllocated();
  return 1;
}

// native BS_WriteValue(BitStream:bs, {PR_ValueType, Float, _}:...);
cell Script::BS_WriteValue(cell *params) {
  AssertMinParams(3, params);

  GET_BS_CHECKED(static_cast<uint32_t>(params[1]), bs);

  for (std::size_t i = 1; i < (params[0] / sizeof(cell)) - 1; i += 2) {
    const auto type = *GetPhysAddr(params[i + 1]);
    const auto &value = *GetPhysAddr(params[i + 2]);

    switch (type) {
      case PR_STRING:
      case PR_CSTRING: {
        auto str = GetString(params[i + 2]);

        if (type == PR_STRING) {
          bs->Write(str.c_str(), str.size());
        } else {
          stringCompressor->EncodeString(str.c_str(), str.size() + 1, bs);
        }

        break;
      }
      case PR_INT8:
        WriteValue<char>(bs, value);
        break;
      case PR_INT16:
        WriteValue<short>(bs, value);
        break;
      case PR_INT32:
        WriteValue<int>(bs, value);
        break;
      case PR_UINT8:
        WriteValue<unsigned char>(bs, value);
        break;
      case PR_UINT16:
        WriteValue<unsigned short>(bs, value);
        break;
      case PR_UINT32:
        WriteValue<unsigned int>(bs, value);
        break;
      case PR_FLOAT:
        WriteValue<float>(bs, value);
        break;
      case PR_BOOL:
        WriteValue<bool>(bs, value);
        break;
      case PR_CINT8:
        WriteValue<char, true>(bs, value);
        break;
      case PR_CINT16:
        WriteValue<short, true>(bs, value);
        break;
      case PR_CINT32:
        WriteValue<int, true>(bs, value);
        break;
      case PR_CUINT8:
        WriteValue<unsigned char, true>(bs, value);
        break;
      case PR_CUINT16:
        WriteValue<unsigned short, true>(bs, value);
        break;
      case PR_CUINT32:
        WriteValue<unsigned int, true>(bs, value);
        break;
      case PR_CFLOAT:
        WriteValue<float, true>(bs, value);
        break;
      case PR_CBOOL:
        WriteValue<bool, true>(bs, value);
        break;
      case PR_BITS: {
        const auto number_of_bits = *GetPhysAddr(params[i + 3]);
        if (number_of_bits <= 0 || number_of_bits > (sizeof(cell) * 8)) {
          throw std::runtime_error{"Invalid number of bits"};
        }

        bs->WriteBits(reinterpret_cast<const unsigned char *>(&value),
                      number_of_bits, true);

        i++;

        break;
      }
      case PR_FLOAT3:
      case PR_FLOAT4: {
        const std::size_t arr_size = (type == PR_FLOAT3 ? 3 : 4);
        const auto arr = &value;

        for (std::size_t index{}; index < arr_size; index++) {
          WriteValue<float>(bs, arr[index]);
        }

        break;
      }
      case PR_VECTOR:
      case PR_NORM_QUAT: {
        const auto arr = reinterpret_cast<const float *>(&value);

        if (type == PR_VECTOR) {
          bs->WriteVector(arr[0], arr[1], arr[2]);
        } else {
          bs->WriteNormQuat(arr[0], arr[1], arr[2], arr[3]);
        }

        break;
      }
      case PR_STRING8:
      case PR_STRING32: {
        auto str = GetString(params[i + 2]);

        if (type == PR_STRING8) {
          WriteValue<unsigned char>(bs, str.size());
        } else {
          WriteValue<unsigned int>(bs, str.size());
        }

        bs->Write(str.c_str(), str.size());

        break;
      }
      case PR_IGNORE_BITS: {
        bs->SetWriteOffset(bs->GetWriteOffset() + value);
        break;
      }
      default: {
        throw std::runtime_error{"Invalid type of value"};
      }
    }
  }

  return 1;
}

// native BS_ReadValue(BitStream:bs, {PR_ValueType, Float, _}:...);
cell Script::BS_ReadValue(cell *params) {
  AssertMinParams(3, params);

  GET_BS_CHECKED(static_cast<uint32_t>(params[1]), bs);

  for (std::size_t i = 1; i < (params[0] / sizeof(cell)) - 1; i += 2) {
    const auto type = *GetPhysAddr(params[i + 1]);
    auto &value = *GetPhysAddr(params[i + 2]);

    switch (type) {
      case PR_STRING:
      case PR_CSTRING: {
        const auto size = *GetPhysAddr(params[i + 3]);

        std::unique_ptr<char[]> str{new char[size + 1]{}};

        if (type == PR_STRING) {
          bs->Read(str.get(), size);
        } else {
          stringCompressor->DecodeString(str.get(), size, bs);
        }

        SetString(&value, str.get(), size + 1);

        i++;

        break;
      }
      case PR_INT8:
        value = ReadValue<char>(bs);
        break;
      case PR_INT16:
        value = ReadValue<short>(bs);
        break;
      case PR_INT32:
        value = ReadValue<int>(bs);
        break;
      case PR_UINT8:
        value = ReadValue<unsigned char>(bs);
        break;
      case PR_UINT16:
        value = ReadValue<unsigned short>(bs);
        break;
      case PR_UINT32:
        value = ReadValue<unsigned int>(bs);
        break;
      case PR_FLOAT:
        value = ReadValue<float>(bs);
        break;
      case PR_BOOL:
        value = ReadValue<bool>(bs);
        break;
      case PR_CINT8:
        value = ReadValue<char, true>(bs);
        break;
      case PR_CINT16:
        value = ReadValue<short, true>(bs);
        break;
      case PR_CINT32:
        value = ReadValue<int, true>(bs);
        break;
      case PR_CUINT8:
        value = ReadValue<unsigned char, true>(bs);
        break;
      case PR_CUINT16:
        value = ReadValue<unsigned short, true>(bs);
        break;
      case PR_CUINT32:
        value = ReadValue<unsigned int, true>(bs);
        break;
      case PR_CFLOAT:
        value = ReadValue<float, true>(bs);
        break;
      case PR_CBOOL:
        value = ReadValue<bool, true>(bs);
        break;
      case PR_BITS: {
        const auto number_of_bits = *GetPhysAddr(params[i + 3]);
        if (number_of_bits <= 0 || number_of_bits > (sizeof(cell) * 8)) {
          throw std::runtime_error{"Invalid number of bits"};
        }

        bs->ReadBits(reinterpret_cast<unsigned char *>(&value), number_of_bits,
                     true);

        i++;

        break;
      }
      case PR_FLOAT3:
      case PR_FLOAT4: {
        const std::size_t arr_size = (type == PR_FLOAT3 ? 3 : 4);
        auto arr = &value;

        for (std::size_t index{}; index < arr_size; index++) {
          arr[index] = ReadValue<float>(bs);
        }

        break;
      }
      case PR_VECTOR:
      case PR_NORM_QUAT: {
        auto arr = reinterpret_cast<float *>(&value);

        if (type == PR_VECTOR) {
          bs->ReadVector(arr[0], arr[1], arr[2]);
        } else {
          bs->ReadNormQuat(arr[0], arr[1], arr[2], arr[3]);
        }

        break;
      }
      case PR_STRING8:
      case PR_STRING32: {
        const auto max_size = *GetPhysAddr(params[i + 3]) - 1;

        cell size{};

        if (type == PR_STRING8) {
          size = ReadValue<unsigned char>(bs);
        } else {
          size = ReadValue<unsigned int>(bs);
        }

        if (size > 0) {
          if (size > max_size) {
            Log("%s: Warning! size (%d) > max_size (%d) "
                "(PR_STRING8/PR_STRING32)",
                __FUNCTION__, size, max_size);

            size = max_size;
          }

          std::unique_ptr<char[]> str{new char[size + 1]{}};

          bs->Read(str.get(), size);

          SetString(&value, str.get(), size + 1);
        }

        i++;

        break;
      }
      case PR_IGNORE_BITS: {
        bs->IgnoreBits(value);
        break;
      }
      default: {
        throw std::runtime_error{"Invalid type of value"};
      }
    }
  }

  return 1;
}

bool Script::OnLoad() {
  config_ = Plugin::Get().GetConfig();

  int num_publics{};
  amx_->NumPublics(&num_publics);

  for (int index{}; index < num_publics; index++) {
    std::string public_name = GetPublicName(index);
    if (std::regex_match(public_name, regex_reg_handler_public_name_)) {
      publics_reg_handler_.push_back(MakePublic(public_name));
    } else if (public_name == "OnIncomingPacket") {
      InitPublic(PR_INCOMING_PACKET, public_name);
    } else if (public_name == "OnIncomingRPC") {
      InitPublic(PR_INCOMING_RPC, public_name);
    } else if (public_name == "OnOutgoingPacket") {
      InitPublic(PR_OUTGOING_PACKET, public_name);
    } else if (public_name == "OnOutgoingRPC") {
      InitPublic(PR_OUTGOING_RPC, public_name);
    }

    // backward compatibility
    if (public_name == "OnOutcomingPacket") {
      public_on_outcoming_packet_ =
          MakePublic(public_name, config_->UseCaching());
    } else if (public_name == "OnOutcomingRPC") {
      public_on_outcoming_rpc_ = MakePublic(public_name, config_->UseCaching());
    }
  }

  return true;
}

bool Script::ExecPublic(const PublicPtr &pub, int player_id,
                        unsigned char event_id, uint32_t bsId) {
  if (!pub || !pub->Exists()) {
    return true;
  }

  auto bs = BitStreamPool::Instance.GetBSFromID(bsId);
  if (bs == nullptr) {
    return true;
  }

  bs->resetReadPointer();

  return pub->Exec(player_id, static_cast<cell>(event_id), bsId);
}

void Script::InitPublic(PR_EventType type, const std::string &public_name) {
  publics_.at(type) = MakePublic(public_name, config_->UseCaching());
}

void Script::InitHandler(unsigned char event_id, const std::string &public_name,
                         PR_EventType type) {
  auto &plugin = Plugin::Get();

  auto pub = MakePublic(public_name, config_->UseCaching());
  if (!pub->Exists()) {
    throw std::runtime_error{"Public " + public_name + " does not exist"};
  }

  handlers_.at(type).at(event_id).push_back(pub);

  if (type == PR_INCOMING_CUSTOM_RPC) {
    plugin.SetCustomRPC(event_id);
  }
}

void Script::InitHandlers() {
  for (const auto &pub : publics_reg_handler_) {
    if (pub && pub->Exists()) {
      pub->Exec();
    }
  }
}

template <typename T, bool compressed>
void Script::WriteValue(BitStream *bs, cell value) {
  T prepared_value{};

  if constexpr (std::is_same<float, T>::value) {
    prepared_value = amx_ctof(value);
  } else {
    prepared_value = static_cast<T>(value);
  }

  if constexpr (compressed) {
    bs->WriteCompressed<T>(prepared_value);
  } else {
    bs->Write<T>(prepared_value);
  }
}

template <typename T, bool compressed>
cell Script::ReadValue(BitStream *bs) {
  T value{};

  if constexpr (compressed) {
    bs->ReadCompressed<T>(value);
  } else {
    bs->Read<T>(value);
  }

  if constexpr (std::is_same<float, T>::value) {
    return amx_ftoc(value);
  }

  return static_cast<cell>(value);
}
