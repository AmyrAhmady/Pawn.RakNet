#ifndef NATIVES_H_
#define NATIVES_H_

namespace Natives {
    // native BS_RPC(BitStream:bs, playerid, rpcid, PR_PacketPriority:priority = HIGH_PRIORITY, PR_PacketReliability:reliability = RELIABLE_ORDERED);
    cell AMX_NATIVE_CALL n_BS_RPC(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(5, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            const int
                player_id = static_cast<int>(params[2]),
                rpc_id = static_cast<int>(params[3]),
                priority = static_cast<int>(params[4]),
                reliability = static_cast<int>(params[5]);

            return static_cast<cell>(Functions::SendRPC(player_id, rpc_id, bs, priority, reliability));
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_Send(BitStream:bs, playerid, PR_PacketPriority:priority = HIGH_PRIORITY, PR_PacketReliability:reliability = RELIABLE_ORDERED);
    cell AMX_NATIVE_CALL n_BS_Send(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(4, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            const int
                player_id = static_cast<int>(params[2]),
                priority = static_cast<int>(params[3]),
                reliability = static_cast<int>(params[4]);

            return static_cast<cell>(Functions::SendPacket(player_id, bs, priority, reliability));
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_EmulateIncomingRPC(BitStream:bs, playerid, rpcid);
    cell AMX_NATIVE_CALL n_BS_EmulateIncomingRPC(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(3, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            const int
                player_id = static_cast<int>(params[2]),
                rpc_id = static_cast<int>(params[3]);

            const auto &handler = Hooks::original_rpc.at(rpc_id);

            if (!handler) {
                throw std::runtime_error{"invalid rpcid"};
            }

            RPCParameters RPCParams;
            RPCParams.numberOfBitsOfData = bs->GetNumberOfBitsUsed();
            RPCParams.sender = Functions::GetPlayerIDFromIndex(player_id);

            if (RPCParams.numberOfBitsOfData) {
                RPCParams.input = bs->GetData();
            }

            handler(&RPCParams);

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BitStream:BS_New();
    cell AMX_NATIVE_CALL n_BS_New(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(0, params);

            return reinterpret_cast<cell>(new RakNet::BitStream{});
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_Delete(&BitStream:bs);
    cell AMX_NATIVE_CALL n_BS_Delete(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(1, params);

            cell *cptr{};

            if (amx_GetAddr(amx, params[1], &cptr) != AMX_ERR_NONE) {
                throw std::runtime_error{"invalid param"};
            }

            if (!*cptr) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            delete reinterpret_cast<RakNet::BitStream *>(*cptr);

            *cptr = 0;

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_Reset(BitStream:bs);
    cell AMX_NATIVE_CALL n_BS_Reset(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(1, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            bs->Reset();

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_ResetReadPointer(BitStream:bs);
    cell AMX_NATIVE_CALL n_BS_ResetReadPointer(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(1, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            bs->ResetReadPointer();

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_ResetWritePointer(BitStream:bs);
    cell AMX_NATIVE_CALL n_BS_ResetWritePointer(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(1, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            bs->ResetWritePointer();

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_IgnoreBits(BitStream:bs, number_of_bits);
    cell AMX_NATIVE_CALL n_BS_IgnoreBits(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(2, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            const int number_of_bits = static_cast<int>(params[2]);

            bs->IgnoreBits(number_of_bits);

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_SetWriteOffset(BitStream:bs, offset);
    cell AMX_NATIVE_CALL n_BS_SetWriteOffset(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(2, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            const int offset = static_cast<int>(params[2]);

            bs->SetWriteOffset(offset);

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_GetWriteOffset(BitStream:bs, &offset);
    cell AMX_NATIVE_CALL n_BS_GetWriteOffset(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(2, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            cell *cptr{};

            if (amx_GetAddr(amx, params[2], &cptr) != AMX_ERR_NONE) {
                throw std::runtime_error{"invalid param"};
            }

            *cptr = static_cast<cell>(bs->GetWriteOffset());

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_SetReadOffset(BitStream:bs, offset);
    cell AMX_NATIVE_CALL n_BS_SetReadOffset(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(2, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            const int offset = static_cast<int>(params[2]);

            bs->SetReadOffset(offset);

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_GetReadOffset(BitStream:bs, &offset);
    cell AMX_NATIVE_CALL n_BS_GetReadOffset(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(2, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            cell *cptr{};

            if (amx_GetAddr(amx, params[2], &cptr) != AMX_ERR_NONE) {
                throw std::runtime_error{"invalid param"};
            }

            *cptr = static_cast<cell>(bs->GetReadOffset());

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_GetNumberOfBitsUsed(BitStream:bs, &number);
    cell AMX_NATIVE_CALL n_BS_GetNumberOfBitsUsed(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(2, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            cell *cptr{};

            if (amx_GetAddr(amx, params[2], &cptr) != AMX_ERR_NONE) {
                throw std::runtime_error{"invalid param"};
            }

            *cptr = static_cast<cell>(bs->GetNumberOfBitsUsed());

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_GetNumberOfBytesUsed(BitStream:bs, &number);
    cell AMX_NATIVE_CALL n_BS_GetNumberOfBytesUsed(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(2, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            cell *cptr{};

            if (amx_GetAddr(amx, params[2], &cptr) != AMX_ERR_NONE) {
                throw std::runtime_error{"invalid param"};
            }

            *cptr = static_cast<cell>(bs->GetNumberOfBytesUsed());

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_GetNumberOfUnreadBits(BitStream:bs, &number);
    cell AMX_NATIVE_CALL n_BS_GetNumberOfUnreadBits(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(2, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            cell *cptr{};

            if (amx_GetAddr(amx, params[2], &cptr) != AMX_ERR_NONE) {
                throw std::runtime_error{"invalid param"};
            }

            *cptr = static_cast<cell>(bs->GetNumberOfUnreadBits());

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_GetNumberOfBitsAllocated(BitStream:bs, &number);
    cell AMX_NATIVE_CALL n_BS_GetNumberOfBitsAllocated(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(2, params);

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            cell *cptr{};

            if (amx_GetAddr(amx, params[2], &cptr) != AMX_ERR_NONE) {
                throw std::runtime_error{"invalid param"};
            }

            *cptr = static_cast<cell>(bs->GetNumberOfBitsAllocated());

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native BS_WriteValue(BitStream:bs, {Float,_}:...);
    cell AMX_NATIVE_CALL n_BS_WriteValue(AMX *amx, cell *params) {
        try {
            if (params[0] < (sizeof(cell) * 3)) {
                throw std::runtime_error{"number of parameters must be >= 3"};
            }

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            cell *cptr_type{}, *cptr_value{};

            for (std::size_t i = 1; i < (params[0] / sizeof(cell)) - 1; i += 2) {
                if (
                    amx_GetAddr(amx, params[i + 1], &cptr_type) != AMX_ERR_NONE ||
                    amx_GetAddr(amx, params[i + 2], &cptr_value) != AMX_ERR_NONE
                ) {
                    throw std::runtime_error{"invalid param"};
                }

                const auto type = static_cast<PR_ValueType>(*cptr_type);

                switch (type) {
                    case PR_STRING: {
                        int size{}; amx_StrLen(cptr_value, &size);

                        char *str = new char[size + 1]{};

                        amx_GetString(str, cptr_value, 0, size + 1);

                        bs->Write(str, size);

                        delete[] str;

                        break;
                    }
                    case PR_CSTRING: {
                        int size{}; amx_StrLen(cptr_value, &size);

                        char *str = new char[size + 1]{};

                        amx_GetString(str, cptr_value, 0, size + 1);

                        stringCompressor->EncodeString(str, size + 1, bs);

                        delete[] str;

                        break;
                    }
                    case PR_INT8:
                        bs->Write(static_cast<char>(*cptr_value));
                        break;
                    case PR_INT16:
                        bs->Write(static_cast<short>(*cptr_value));
                        break;
                    case PR_INT32:
                        bs->Write(static_cast<int>(*cptr_value));
                        break;
                    case PR_UINT8:
                        bs->Write(static_cast<unsigned char>(*cptr_value));
                        break;
                    case PR_UINT16:
                        bs->Write(static_cast<unsigned short>(*cptr_value));
                        break;
                    case PR_UINT32:
                        bs->Write(static_cast<unsigned int>(*cptr_value));
                        break;
                    case PR_FLOAT:
                        bs->Write(amx_ctof(*cptr_value));
                        break;
                    case PR_BOOL:
                        bs->Write(!!(*cptr_value));
                        break;
                    case PR_CINT8:
                        bs->WriteCompressed(static_cast<char>(*cptr_value));
                        break;
                    case PR_CINT16:
                        bs->WriteCompressed(static_cast<short>(*cptr_value));
                        break;
                    case PR_CINT32:
                        bs->WriteCompressed(static_cast<int>(*cptr_value));
                        break;
                    case PR_CUINT8:
                        bs->WriteCompressed(static_cast<unsigned char>(*cptr_value));
                        break;
                    case PR_CUINT16:
                        bs->WriteCompressed(static_cast<unsigned short>(*cptr_value));
                        break;
                    case PR_CUINT32:
                        bs->WriteCompressed(static_cast<unsigned int>(*cptr_value));
                        break;
                    case PR_CFLOAT:
                        bs->WriteCompressed(amx_ctof(*cptr_value));
                        break;
                    case PR_CBOOL:
                        bs->WriteCompressed(!!(*cptr_value));
                        break;
                    case PR_BITS: {
                        cell *cptr_number_of_bits{}; amx_GetAddr(amx, params[i + 3], &cptr_number_of_bits);

                        int number_of_bits = static_cast<int>(*cptr_number_of_bits);

                        if (number_of_bits <= 0 || number_of_bits > (sizeof(cell) * 8)) {
                            throw std::runtime_error{"invalid number of bits"};
                        }

                        bs->WriteBits(reinterpret_cast<unsigned char *>(cptr_value), number_of_bits, true);

                        ++i;

                        break;
                    }
                    default: {
                        throw std::runtime_error{"invalid type of value"};
                    }
                }
            }

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    template<typename T>
    struct Value {
        static inline cell Read(RakNet::BitStream *bs) {
            T value{};

            bs->Read<T>(value);

            return static_cast<cell>(value);
        }

        static inline cell ReadCompressed(RakNet::BitStream *bs) {
            T value{};

            bs->ReadCompressed<T>(value);

            return static_cast<cell>(value);
        }
    };

    template<>
    struct Value<float> {
        static inline cell Read(RakNet::BitStream *bs) {
            float value{};

            bs->Read<float>(value);

            return amx_ftoc(value);
        }

        static inline cell ReadCompressed(RakNet::BitStream *bs) {
            float value{};

            bs->ReadCompressed<float>(value);

            return amx_ftoc(value);
        }
    };

    // native BS_ReadValue(BitStream:bs, {Float,_}:...);
    cell AMX_NATIVE_CALL n_BS_ReadValue(AMX *amx, cell *params) {
        try {
            if (params[0] < sizeof(cell) * 3) {
                throw std::runtime_error{"number of parameters must be >= 3"};
            }

            const auto bs = reinterpret_cast<RakNet::BitStream *>(params[1]);

            if (!bs) {
                throw std::runtime_error{"invalid BitStream handle"};
            }

            cell *cptr_type{}, *cptr_value{};

            for (std::size_t i = 1; i < (params[0] / sizeof(cell)) - 1; i += 2) {
                if (
                    amx_GetAddr(amx, params[i + 1], &cptr_type) != AMX_ERR_NONE ||
                    amx_GetAddr(amx, params[i + 2], &cptr_value) != AMX_ERR_NONE
                ) {
                    throw std::runtime_error{"invalid param"};
                }

                const auto type = static_cast<PR_ValueType>(*cptr_type);

                switch (type) {
                    case PR_STRING: {
                        cell *cptr_size{}; amx_GetAddr(amx, params[i + 3], &cptr_size);

                        std::size_t size = *cptr_size;

                        char *str = new char[size + 1]{};

                        bs->Read(str, size);

                        Functions::SetAmxString(amx, params[i + 2], str, size);

                        delete[] str;

                        ++i;

                        break;
                    }
                    case PR_CSTRING: {
                        cell *cptr_size{}; amx_GetAddr(amx, params[i + 3], &cptr_size);

                        std::size_t size = *cptr_size;

                        char *str = new char[size + 1]{};

                        stringCompressor->DecodeString(str, size, bs);

                        Functions::SetAmxString(amx, params[i + 2], str, size);

                        delete[] str;

                        ++i;

                        break;
                    }
                    case PR_INT8:
                        *cptr_value = Value<char>::Read(bs);
                        break;
                    case PR_INT16:
                        *cptr_value = Value<short>::Read(bs);
                        break;
                    case PR_INT32:
                        *cptr_value = Value<int>::Read(bs);
                        break;
                    case PR_UINT8:
                        *cptr_value = Value<unsigned char>::Read(bs);
                        break;
                    case PR_UINT16:
                        *cptr_value = Value<unsigned short>::Read(bs);
                        break;
                    case PR_UINT32:
                        *cptr_value = Value<unsigned int>::Read(bs);
                        break;
                    case PR_FLOAT:
                        *cptr_value = Value<float>::Read(bs);
                        break;
                    case PR_BOOL:
                        *cptr_value = Value<bool>::Read(bs);
                        break;
                    case PR_CINT8:
                        *cptr_value = Value<char>::ReadCompressed(bs);
                        break;
                    case PR_CINT16:
                        *cptr_value = Value<short>::ReadCompressed(bs);
                        break;
                    case PR_CINT32:
                        *cptr_value = Value<int>::ReadCompressed(bs);
                        break;
                    case PR_CUINT8:
                        *cptr_value = Value<unsigned char>::ReadCompressed(bs);
                        break;
                    case PR_CUINT16:
                        *cptr_value = Value<unsigned short>::ReadCompressed(bs);
                        break;
                    case PR_CUINT32:
                        *cptr_value = Value<unsigned int>::ReadCompressed(bs);
                        break;
                    case PR_CFLOAT:
                        *cptr_value = Value<float>::ReadCompressed(bs);
                        break;
                    case PR_CBOOL:
                        *cptr_value = Value<bool>::ReadCompressed(bs);
                        break;
                    case PR_BITS: {
                        cell *cptr_number_of_bits{}; amx_GetAddr(amx, params[i + 3], &cptr_number_of_bits);

                        int number_of_bits = static_cast<int>(*cptr_number_of_bits);

                        if (number_of_bits <= 0 || number_of_bits > (sizeof(cell) * 8)) {
                            throw std::runtime_error{"invalid number of bits"};
                        }

                        bs->ReadBits(reinterpret_cast<unsigned char *>(cptr_value), number_of_bits, true);

                        ++i;

                        break;
                    }
                    default: {
                        throw std::runtime_error{"invalid type of value"};
                    }
                }
            }

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    // native PR_RegHandler(id, const publicname[], PR_HandlerType:type);
    cell AMX_NATIVE_CALL n_PR_RegHandler(AMX *amx, cell *params) {
        try {
            Functions::AssertParams(3, params);

            Scripts::RegisterHandler(
                amx,
                static_cast<int>(params[1]),
                Functions::GetAmxString(amx, params[2]),
                static_cast<PR_HandlerType>(params[3])
            );

            return 1;
        } catch (const std::exception &e) {
            Logger::instance()->Write("[%s] %s: %s", Settings::kPluginName, __FUNCTION__, e.what());
        }

        return 0;
    }

    void Register(AMX *amx) {
        const std::vector<AMX_NATIVE_INFO> natives{
            {"BS_RPC", n_BS_RPC},
            {"BS_Send", n_BS_Send},

            {"BS_EmulateIncomingRPC", n_BS_EmulateIncomingRPC},

            {"BS_New", n_BS_New},
            {"BS_Delete", n_BS_Delete},

            {"BS_Reset", n_BS_Reset},
            {"BS_ResetReadPointer", n_BS_ResetReadPointer},
            {"BS_ResetWritePointer", n_BS_ResetWritePointer},
            {"BS_IgnoreBits", n_BS_IgnoreBits},

            {"BS_SetWriteOffset", n_BS_SetWriteOffset},
            {"BS_GetWriteOffset", n_BS_GetWriteOffset},
            {"BS_SetReadOffset", n_BS_SetReadOffset},
            {"BS_GetReadOffset", n_BS_GetReadOffset},

            {"BS_GetNumberOfBitsUsed", n_BS_GetNumberOfBitsUsed},
            {"BS_GetNumberOfBytesUsed", n_BS_GetNumberOfBytesUsed},
            {"BS_GetNumberOfUnreadBits", n_BS_GetNumberOfUnreadBits},
            {"BS_GetNumberOfBitsAllocated", n_BS_GetNumberOfBitsAllocated},

            {"BS_WriteValue", n_BS_WriteValue},
            {"BS_ReadValue", n_BS_ReadValue},

            {"PR_RegHandler", n_PR_RegHandler}
        };

        amx_Register(amx, natives.data(), natives.size());
    }
};

#endif // NATIVES_H_
