# lua-resty-des

support des_ecb, des_cbc

support zero_padding

### decrypt
    local des = require("resty.des");
    local str = "uhbGoCVxJa8=";
    local key = "12345678";
    local des_ecb, err = des:new(key, des.cipher("ecb"));
    if (not des_ecb) then
        ngx.say(err);
        return;
    end
 
    str = ngx.decode_base64(str);
    local origin_str = des_ecb:decrypt(str);
    if (not origin_str) then
        ngx.say("decrypt err");
        return;
    end
 
    ngx.say(origin_str);
    

### encrypt
    local des = require("resty.des");
    local origin_str = "hello";
    local key = "12345678";
    local des_ecb, err = des:new(key, des.cipher("ecb"));
    if (not des_ecb) then
        ngx.say(err);
        return;
    end
 
    local str = des_ecb:encrypt(origin_str);
    str = ngx.encode_base64(str);
 
    ngx.say(str);
