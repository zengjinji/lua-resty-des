
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local ffi_copy = ffi.copy
local C = ffi.C
local setmetatable = setmetatable
local type = type


local _M = { _VERSION = '0.0.1' }

local mt = { __index = _M }

local is_openssl_1_1 = false;
if (string.find(ngx.config.nginx_configure(), "DOPENSSL_VER_1_1")) then
    is_openssl_1_1 = true;
end

-- aes.lua ffi.cdef declare openssl function
local declare = require("resty.aes")

ffi.cdef[[
const EVP_CIPHER *EVP_des_ecb(void);
const EVP_CIPHER *EVP_des_cbc(void);
]]

local ctx_ptr_type = ffi.typeof("EVP_CIPHER_CTX[1]")


local cipher
cipher = function (_cipher)
    local _cipher = _cipher or "ecb"
    local func = "EVP_des_" .. _cipher
    if C[func] then
        return { cipher=_cipher, method=C[func]()}
    else
        return nil
    end
end
_M.cipher = cipher


function _M.new(self, key, _cipher, _hash)
    if #key < 8 then
        return nil, "key length must be 8"
    end

    local encrypt_ctx = ffi_new(ctx_ptr_type)
    local decrypt_ctx = ffi_new(ctx_ptr_type)
    local _cipher = _cipher or cipher()
    local gen_key = ffi_new("unsigned char[8]")
    local gen_iv = ffi_new("unsigned char[8]")

    ffi_copy(gen_key, key, 8)

    if type(_hash) == "table" then
        if not _hash.iv or #_hash.iv ~= 8 then
            return nil, "bad iv"
        end

        ffi_copy(gen_iv, _hash.iv, 8)
    end


    if (not is_openssl_1_1) then
        C.EVP_CIPHER_CTX_init(encrypt_ctx)
        C.EVP_CIPHER_CTX_init(decrypt_ctx)
    else
        C.EVP_CIPHER_CTX_reset(encrypt_ctx)
        C.EVP_CIPHER_CTX_reset(decrypt_ctx)
    end

    if C.EVP_EncryptInit_ex(encrypt_ctx, _cipher.method, nil, gen_key, gen_iv) == 0 then
        return nil, "EVP_EncryptInit_ex error"
    end

    if C.EVP_DecryptInit_ex(decrypt_ctx, _cipher.method, nil, gen_key, gen_iv) == 0 then
        return nil, "EVP_DecryptInit_ex error"
    end

    if (not is_openssl_1_1) then
        ffi_gc(encrypt_ctx, C.EVP_CIPHER_CTX_cleanup)
        ffi_gc(decrypt_ctx, C.EVP_CIPHER_CTX_cleanup)
    else
        ffi_gc(encrypt_ctx, C.EVP_CIPHER_CTX_reset)
        ffi_gc(decrypt_ctx, C.EVP_CIPHER_CTX_reset)
    end

    return setmetatable({
        _encrypt_ctx = encrypt_ctx,
        _decrypt_ctx = decrypt_ctx,
    }, mt)
end


function _M.encrypt(self, s, zeropad)
    if zeropad then
        local n = #s % 8;
        if n ~= 0 then
            local t = {"\0", "\0", "\0", "\0", "\0", "\0", "\0", "\0"}
            s = s .. table.concat(t, "", 1, 8 - n)
        end
    end

    local s_len = #s
    local max_len = s_len + 8
    local out = ffi_new("unsigned char[?]", max_len)
    local out_len = ffi_new("int[1]")
    local tmp_len = ffi_new("int[1]")
    local ctx = self._encrypt_ctx

    if C.EVP_EncryptInit_ex(ctx, nil, nil, nil, nil) == 0 then
        return nil, "EVP_EncryptInit_ex error"
    end

    if zeropad then
        if C.EVP_CIPHER_CTX_set_padding(ctx, 0) == 0 then
            return nil, "EVP_CIPHER_CTX_set_padding error"
        end
    end

    if C.EVP_EncryptUpdate(ctx, out, out_len, s, s_len) ~= 1 then
        return nil, "EVP_EncryptUpdate error"
    end

    if C.EVP_EncryptFinal_ex(ctx, out + out_len[0], tmp_len) == 0 then
        return nil, "EVP_EncryptFinal_ex error"
    end

    return ffi_str(out, out_len[0] + tmp_len[0])
end


function _M.decrypt(self, s, zeropad)
    local s_len = #s
    local out = ffi_new("unsigned char[?]", s_len)
    local out_len = ffi_new("int[1]")
    local tmp_len = ffi_new("int[1]")
    local ctx = self._decrypt_ctx

    if C.EVP_DecryptInit_ex(ctx, nil, nil, nil, nil) == 0 then
        return nil, "EVP_DecryptInit_ex error"
    end

    if zeropad then
        if C.EVP_CIPHER_CTX_set_padding(ctx, 0) == 0 then
            return nil, "EVP_CIPHER_CTX_set_padding error"
        end
    end

    if C.EVP_DecryptUpdate(ctx, out, out_len, s, s_len) == 0 then
        return nil, "EVP_DecryptUpdate error"
    end

    if C.EVP_DecryptFinal_ex(ctx, out + out_len[0], tmp_len) == 0 then
        return nil, "EVP_DecryptFinal_ex error"
    end

    local str = ffi_str(out, out_len[0] + tmp_len[0])

    if zeropad then
        local pos = string.find(str, "\0")
        if pos then
            str = string.sub(str, 1, pos-1)
        end
    end

    return str;
end


return _M
