/*
 * Copyright 2001-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>

#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include "internal/refcount.h"
#include "crypto/ec.h"

#if defined(__SUNPRO_C)
# if __SUNPRO_C >= 0x520
#  pragma error_messages (off,E_ARRAY_OF_INCOMPLETE_NONAME,E_ARRAY_OF_INCOMPLETE)
# endif
#endif

/* Use default functions for poin2oct, oct2point and compressed coordinates */
#define EC_FLAGS_DEFAULT_OCT    0x1

/* Use custom formats for EC_GROUP, EC_POINT and EC_KEY */
#define EC_FLAGS_CUSTOM_CURVE   0x2

/* Curve does not support signing operations */
#define EC_FLAGS_NO_SIGN        0x4

#ifdef OPENSSL_NO_DEPRECATED_3_0
typedef struct ec_method_st EC_METHOD;
#endif

/*
 * Structure details are not part of the exported interface, so all this may
 * change in future versions.
 */

struct ec_method_st {
    /* Various method flags */
    int flags;
    /* used by EC_METHOD_get_field_type: */
    int field_type;             /* a NID */
    /*
     * used by EC_GROUP_new, EC_GROUP_free, EC_GROUP_clear_free,
     * EC_GROUP_copy:
     */
    int (*group_init) (EC_GROUP *);
    void (*group_finish) (EC_GROUP *);
    void (*group_clear_finish) (EC_GROUP *);
    int (*group_copy) (EC_GROUP *, const EC_GROUP *);
    /* used by EC_GROUP_set_curve, EC_GROUP_get_curve: */
    /* 设置和获取这个曲线的参数，素数域p， 曲线参数a、b，这样可以确定使用哪个椭圆曲线方程 */
    int (*group_set_curve) (EC_GROUP *, const BIGNUM *p, const BIGNUM *a,
                            const BIGNUM *b, BN_CTX *);
    int (*group_get_curve) (const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b,
                            BN_CTX *);
    /* used by EC_GROUP_get_degree: */
    /* 函数会返回该椭圆曲线的阶数,即在该椭圆曲线上定义的点群的阶数。 */
    int (*group_get_degree) (const EC_GROUP *);
    /* group_order_bits函数用于获取EC_GROUP表示的椭圆曲线点群的阶数的二进制位长度。 */
    int (*group_order_bits) (const EC_GROUP *);
    /* used by EC_GROUP_check: */
    /* group_check_discriminant函数用于检查一个EC_GROUP的判别式是否合法。 
        如果判别式为0,表示曲线方程参数不合法,不能定义一个合法的椭圆曲线。
        这个函数用于在设置曲线参数后对其合法性进行检查,确保定义的椭圆曲线合理正确。
        它返回一个整数表示检查结果:0表示判别式不合法,1表示判别式合法。
    */
    int (*group_check_discriminant) (const EC_GROUP *, BN_CTX *);
    /*
     * used by EC_POINT_new, EC_POINT_free, EC_POINT_clear_free,
     * EC_POINT_copy:
     */
    int (*point_init) (EC_POINT *);
    void (*point_finish) (EC_POINT *);
    void (*point_clear_finish) (EC_POINT *);
    int (*point_copy) (EC_POINT *, const EC_POINT *);
    /*-
     * used by EC_POINT_set_to_infinity,
     * EC_POINT_set_Jprojective_coordinates_GFp,
     * EC_POINT_get_Jprojective_coordinates_GFp,
     * EC_POINT_set_affine_coordinates,
     * EC_POINT_get_affine_coordinates,
     * EC_POINT_set_compressed_coordinates:
     */
    /*-
     * point_set_to_infinity函数用于将一个椭圆曲线点设置为“无穷远点”。
     * 通常用来验证一个点是否是无穷远点，很多时候需要验证传入的点为非无穷远点。
     */
    int (*point_set_to_infinity) (const EC_GROUP *, EC_POINT *);
    /*-
     * point_set_affine_coordinates函数用于为一个椭圆曲线点设置affine坐标.
     * 它的参数包含:
     * const EC_GROUP *group:点所在的椭圆曲线组.
     * EC_POINT *point:要设置坐标的点.
     * const BIGNUM *x:点的x坐标.
     * const BIGNUM *y:点的y坐标.
     * BN_CTX *ctx:坐标计算的临时变量上下文.
     * 该函数会将point表示的曲线点的坐标设置为传入的x和y值.
     * 这里的坐标是仿射坐标,是曲线上点的一种直接表示法。设置了坐标后,该点就可以参与椭圆曲线的点加法或标量乘法运算.
     */
    int (*point_set_affine_coordinates) (const EC_GROUP *, EC_POINT *,
                                         const BIGNUM *x, const BIGNUM *y,
                                         BN_CTX *);
    /*-
     * point_get_affine_coordinates函数用于获取一个椭圆曲线点的仿射坐标.
     * 它的参数包含:
     * const EC_GROUP *group:点所在的椭圆曲线组.
     * const EC_POINT *point:要获取坐标的点.
     * BIGNUM *x:保存x坐标的大数对象.
     * BIGNUM *y:保存y坐标的大数对象.
     * BN_CTX *ctx:坐标转换的临时变量上下文.
     * 该函数会提取point表示的曲线点的当前坐标,并存储到输出参数x和y中.
     * 如果点当前不是以仿射坐标表达,会先进行转换.
     * 它返回1表示获取坐标成功,0表示失败(比如点为无穷远点时).
     * 调用者通过传入BIGNUM类型的x和y指针获取到曲线点的仿射坐标表示.
    */
    int (*point_get_affine_coordinates) (const EC_GROUP *, const EC_POINT *,
                                         BIGNUM *x, BIGNUM *y, BN_CTX *);
    /*-
     * point_set_compressed_coordinates函数用于为一个椭圆曲线点设置压缩坐标表示。
     * 
     * 它的参数包含:
     * 
     * const EC_GROUP *group: 点所在的椭圆曲线组。
     * EC_POINT *point: 要设置压缩坐标的点。
     * const BIGNUM *x: 点的x坐标。
     * int y_bit: 点的y坐标的符号位,0表示正,1表示负。
     * BN_CTX *ctx: 坐标转换的临时变量上下文。
     * 椭圆曲线点可以用压缩表示来节省空间,只存储x坐标和y坐标的符号位。
     * 
     * 该函数将根据传入的x坐标和y_bit来设置point表示的曲线点的压缩坐标。
     * 
     * 压缩坐标能减少存储空间,但需要转换才能进行点运算。
    */
    int (*point_set_compressed_coordinates) (const EC_GROUP *, EC_POINT *,
                                             const BIGNUM *x, int y_bit,
                                             BN_CTX *);
    /* used by EC_POINT_point2oct, EC_POINT_oct2point: */
    size_t (*point2oct) (const EC_GROUP *, const EC_POINT *,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *);
    int (*oct2point) (const EC_GROUP *, EC_POINT *, const unsigned char *buf,
                      size_t len, BN_CTX *);
    /* used by EC_POINT_add, EC_POINT_dbl, ECP_POINT_invert: */
    /* r = a + b */
    int (*add) (const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                const EC_POINT *b, BN_CTX *);
    /* r = 2a */
    int (*dbl) (const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
    /* 求p的逆点，逆点加原点等于无穷远点 */
    int (*invert) (const EC_GROUP *, EC_POINT *, BN_CTX *);
    /*
     * used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp:
     */
    /* is_at_infinity函数用于检查一个椭圆曲线点是否为无穷远点O。 */
    int (*is_at_infinity) (const EC_GROUP *, const EC_POINT *);
    int (*is_on_curve) (const EC_GROUP *, const EC_POINT *, BN_CTX *);
    int (*point_cmp) (const EC_GROUP *, const EC_POINT *a, const EC_POINT *b,
                      BN_CTX *);
    /* used by EC_POINT_make_affine, EC_POINTs_make_affine: */
    int (*make_affine) (const EC_GROUP *, EC_POINT *, BN_CTX *);
    int (*points_make_affine) (const EC_GROUP *, size_t num, EC_POINT *[],
                               BN_CTX *);
    /*
     * used by EC_POINTs_mul, EC_POINT_mul, EC_POINT_precompute_mult,
     * EC_POINT_have_precompute_mult (default implementations are used if the
     * 'mul' pointer is 0):
     */
    /*-
     * mul() calculates the value
     *
     *   r := generator * scalar
     *        + points[0] * scalars[0]
     *        + ...
     *        + points[num-1] * scalars[num-1].
     *
     * For a fixed point multiplication (scalar != NULL, num == 0)
     * or a variable point multiplication (scalar == NULL, num == 1),
     * mul() must use a constant time algorithm: in both cases callers
     * should provide an input scalar (either scalar or scalars[0])
     * in the range [0, ec_group_order); for robustness, implementers
     * should handle the case when the scalar has not been reduced, but
     * may treat it as an unusual input, without any constant-timeness
     * guarantee.
     */
    /* generator是曲线基点. 这可以用来计算乘基点kG,或多点乘法等关联密码学运算. */
    int (*mul) (const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                size_t num, const EC_POINT *points[], const BIGNUM *scalars[],
                BN_CTX *);
    int (*precompute_mult) (EC_GROUP *group, BN_CTX *);
    int (*have_precompute_mult) (const EC_GROUP *group);
    /* internal functions */
    /*
     * 'field_mul', 'field_sqr', and 'field_div' can be used by 'add' and
     * 'dbl' so that the same implementations of point operations can be used
     * with different optimized implementations of expensive field
     * operations:
     */
    /* r = a * b */
    int (*field_mul) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                      const BIGNUM *b, BN_CTX *);
    /* r = a ^ 2 */
    int (*field_sqr) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
    /* r = a / b */
    int (*field_div) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                      const BIGNUM *b, BN_CTX *);
    /*-
     * 'field_inv' computes the multiplicative inverse of a in the field,
     * storing the result in r.
     *
     * If 'a' is zero (or equivalent), you'll get an EC_R_CANNOT_INVERT error.
     */
    /*
        该函数会计算a在指定有限域中的乘法逆元,并存储到r中。
        有限域的除法可以通过乘法逆元实现。
        椭圆曲线点运算需要求逆元以实现某些坐标变换和计算。
    */
    int (*field_inv) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
    /* e.g. to Montgomery */
    /*
        field_encode函数用于实现椭圆曲线有限域元素的编码转换。
        其参数包含:
        const EC_GROUP *group: 椭圆曲线组,定义了具体的有限域。
        BIGNUM *r: 保存转换结果的大数对象。
        const BIGNUM *a: 要编码转换的元素。
        BN_CTX *ctx: 临时变量上下文。
        有限域中的元素可以采用不同的编码形式。该函数实现了从一种编码向另一种编码的转换。
        例如可以是到/从Montgomery编码的转换,或不同基编码的转换等。
        编码转换可以加速有限域的运算,或减少存储空间。椭圆曲线运算会调用它。
    */
    int (*field_encode) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                         BN_CTX *);
    /* e.g. from Montgomery */
    int (*field_decode) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                         BN_CTX *);
    /*
        field_set_to_one函数用于将一个椭圆曲线有限域中的元素设置为1。
        其参数包含:
        const EC_GROUP *group: 椭圆曲线组,定义了具体的有限域。
        BIGNUM *r: 要设置为1的元素。
        BN_CTX *ctx: 临时变量上下文。
        有限域中一般会有一个1元素,该函数将r对应的域元素设置为1。
        这主要用于椭圆曲线点运算中某些中间变量的初始化。
        对于不同的有限域表示,设置1的过程也不尽相同。
        函数返回1表示成功将r设置为1,0表示失败。
        设置特定元素值可以加速椭圆曲线运算过程,避免重新构造。
    */
    int (*field_set_to_one) (const EC_GROUP *, BIGNUM *r, BN_CTX *);
    /* private key operations */
    size_t (*priv2oct)(const EC_KEY *eckey, unsigned char *buf, size_t len);
    int (*oct2priv)(EC_KEY *eckey, const unsigned char *buf, size_t len);
    /*
        set_private函数用于为一个EC_KEY设置私钥值。
        其参数包含:
        EC_KEY *eckey:要设置私钥的EC_KEY对象。
        const BIGNUM *priv_key: 私钥值。
        在基于椭圆曲线的公钥密码学中,私钥是一个随机选择的正整数。
        该函数将用priv_key指定的大数设置为eckey所对应的EC私钥。
        设置完私钥后,eckey可以用来生成公钥,进行签名等运算。
        函数返回成功设置的标志:
        1 表示成功设置私钥。
        0 表示失败,可能是由于priv_key无效导致。
        私钥的安全存储和使用是椭圆曲线加密的重要环节。
    */
    int (*set_private)(EC_KEY *eckey, const BIGNUM *priv_key);
    /*
        keygen函数用于生成一个椭圆曲线加密所需的公私钥对。
        它只有一个参数:
        EC_KEY *eckey: 用于保存生成的公私钥的EC_KEY对象。
        该函数会根据传入的EC_KEY所指向的椭圆曲线参数,随机生成一个符合要求的私钥,然后基于该私钥派生生成对应的公钥。
        最后将新生成的公私钥对保存到eckey中。
        这样调用者可以通过一个eckey获取椭圆曲线加密所需的公私钥。
        函数返回1表示密钥对生成成功,0表示失败。
        失败可能由于eckey对象问题,或曲线不合法等原因。
        keypair的生成是椭圆曲线加密应用的第一步。
    */
    int (*keygen)(EC_KEY *eckey);
    /*
        keycheck函数用于检查一个EC_KEY中的公钥是否与私钥对应匹配。
        它的参数只有:
        const EC_KEY *eckey: 要检查的EC_KEY对象。
        该函数会取出eckey中的公钥和私钥,基于私钥重新派生一次公钥,然后比较两个公钥是否匹配。
        如果匹配,说明公钥和私钥是对应同一椭圆曲线点的,确保私钥的合法性。
        如果不匹配,说明公钥是不合法的,私钥与其不匹配。
        这个函数用于验证一个存在的EC密钥对的正确性和一致性。
        函数返回1表示密钥匹配检查成功,0表示失败,密钥不匹配。
        密钥对的检查可防止使用错误的公私钥导致加密失败。
    */
    int (*keycheck)(const EC_KEY *eckey);
    /*
        keygenpub函数用于仅生成椭圆曲线加密所需的公钥。
        它的参数只有:
        EC_KEY *eckey: 用于保存生成公钥的EC_KEY对象。
        该函数会根据eckey中指定的椭圆曲线参数,随机生成对应的公钥,并保存到eckey中。
        它不同于keygen的是,只产生公钥,不生成配对的私钥。
        适用于仅需要公钥的场景,如验证签名等。不会产生任何私钥信息。
        函数返回1表示公钥生成成功,0则失败,主要由于eckey对象问题导致。
        单独的公钥生成可以避免一些场景下的私钥泄露风险。
    */
    int (*keygenpub)(EC_KEY *eckey);
    int (*keycopy)(EC_KEY *dst, const EC_KEY *src);
    /*
        keyfinish函数用于完成一个EC_KEY密钥对的销毁和释放。
        它的参数只有:
        EC_KEY *eckey - 要销毁的EC_KEY对象
        在使用椭圆曲线密码学完成加解密或签名验证后,就不再需要保存密钥信息。
        keyfinish提供了一个销毁eckey所包含密钥信息的接口。
        该函数会清除eckey中存储的私钥信息,释放与之相关的内存资源。
        这可以防止密钥信息留存被恶意获取。
        调用者在不再需要EC密钥时,应该调用keyfinish销毁其信息,以提高安全性。
        销毁密钥对信息也有助于减少内存占用。
        keyfinish返回没有具体返回值,通常不会失败。
    */
    void (*keyfinish)(EC_KEY *eckey);
    /* custom ECDH operation */
    /*
        ecdh_compute_key函数是ECDH密钥协商算法的核心计算函数。
        它的参数包含:
        unsigned char **pout: 保存计算所得共享密钥的缓冲区指针。
        size_t *poutlen: pout缓冲区长度指针。
        const EC_POINT *pub_key: 对方的公钥。
        const EC_KEY *ecdh: 自己的ECDH密钥。
        该函数会利用自己的ECDH私钥和对方的公钥,计算出一个共享的密钥值。
        密钥值将以字节数组形式保存在pout所指内存缓冲区中,长度通过poutlen返回。
        这个共享密钥可以用于双方后的对话加密。
        函数返回成功计算的标志:
        1表示成功,0表示失败。
        失败可能是由于内存错误或传入键无效等原因。
        该函数是完成ECDH协商的最后一步,计算共享密钥。
    */
    int (*ecdh_compute_key)(unsigned char **pout, size_t *poutlen,
                            const EC_POINT *pub_key, const EC_KEY *ecdh);
    /* custom ECDSA */
    /*
        ecdsa_sign_setup函数用于准备和初始化ECDSA签名的相关参数。
        它的参数包含:
        EC_KEY *eckey: 签名用的私钥。
        BN_CTX *ctx: big number上下文。
        BIGNUM **kinvp: 签名随机数k的模n的乘法逆元。
        BIGNUM **rp: 签名参数r。
        在生成ECDSA签名时,需要选择一个随机数k,然后计算k的模n的逆元k^(-1)和参数r。
        该函数会根据传入的私钥,生成这些参数,并通过kinvp和rp指针返回出来。
        调用者接下来可以使用这些参数计算ECDSA签名中的s值。
        返回1表示成功,0失败,主要是由于内存错误或参数无效。
        该函数用于完成ECDSA签名参数准备,是签名前的初始化步骤。
    */
    int (*ecdsa_sign_setup)(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinvp,
                            BIGNUM **rp);
    /*
        ecdsa_sign_sig函数用于生成ECDSA签名的数字签名值。
        它的参数包含:
        const unsigned char *dgst: 消息散列值。
        int dgstlen: 消息散列长度。
        const BIGNUM *kinv: 随机数k的模n的乘法逆元。
        const BIGNUM *r: 签名参数r。
        EC_KEY *eckey: 签名的私钥。
        该函数会根据传入的消息散列,以及之前准备的kinv,r参数,基于eckey指定的私钥,计算出ECDSA签名的数字签名值(r,s)。
        然后将其以ECDSA_SIG结构体形式返回。
        调用者需要提供消息散列和之前ecdsa_sign_setup准备的参数。
        返回NULL表示失败,成功则返回包含签名r,s的ECDSA_SIG。
        该函数是完成ECDSA签名最后一步,计算签名值的核心部分。
    */
    ECDSA_SIG *(*ecdsa_sign_sig)(const unsigned char *dgst, int dgstlen,
                                 const BIGNUM *kinv, const BIGNUM *r,
                                 EC_KEY *eckey);
    /*
        ecdsa_verify_sig函数用于验证ECDSA签名的正确性。
        它的参数包含:
        const unsigned char *dgst: 消息散列值。
        int dgstlen: 消息散列长度。
        const ECDSA_SIG *sig: ECDSA签名值。
        EC_KEY *eckey: 公钥。
        该函数会接收原消息散列、对应的ECDSA签名sig,以及签名的公钥eckey。
        然后根据ECDSA签名算法验证sig对该消息散列的有效性。
        如果验证成功,返回1,表示签名有效。
        如果验证失败,返回0,表示签名无效。
        该函数是完成ECDSA签名验证的核心部分,调用者需要提供正确消息和签名。
        它是椭圆曲线数字签名算法的最后验证步骤。
    */
    int (*ecdsa_verify_sig)(const unsigned char *dgst, int dgstlen,
                            const ECDSA_SIG *sig, EC_KEY *eckey);
    /* Inverse modulo order */
    /*
        field_inverse_mod_ord函数用于计算椭圆曲线群顺序n模逆元。
        其参数包含:
        const EC_GROUP *group: 椭圆曲线组
        BIGNUM *r: 逆元计算结果
        const BIGNUM *x: 要求逆元的元素
        BN_CTX *ctx: BN整数临时变量
        在椭圆曲线密码学中,群指点构成的椭圆曲线加法群,其阶数为n。
        该函数计算x在模n意义下的乘法逆元,即满足 xy ≡ 1 (mod n)的y,存储在r中。
        这里的模n逆运算需要采用扩展欧几里得算法。
        该函数被椭圆曲线签名算法调用,以计算签名参数的值。
        返回1成功,0表示失败,主要是x无穷远点时不存在逆。
        模阶逆运算是椭圆曲线密码学特有的数学工具。
    */
    int (*field_inverse_mod_ord)(const EC_GROUP *, BIGNUM *r,
                                 const BIGNUM *x, BN_CTX *);
    /*
        blind_coordinates函数用于椭圆曲线点坐标的盲化。
        其参数包含:
        const EC_GROUP *group: 椭圆曲线组
        EC_POINT *p: 需要盲化的点
        BN_CTX *ctx: BN变量临时空间
        椭圆曲线加密和签名中,有时需要在不知道确切坐标的情况下操作曲线点,这时可以使用盲化技术。
        该函数会生成一个随机数,使用它来变换点p的坐标,获得一个盲化的新坐标。
        新坐标下点的值相等,但随机化了表示形式。
        这样可以在不暴露真实坐标值的情况下使用该点。
        盲化技术通常用于数字签名等密码协议中,以防止数据泄露。
        函数返回1表示成功,0失败。失败主要是内存错误或传入点无效。
        通过盲化提高了椭圆曲线操作的保密性和安全性。
    */
    int (*blind_coordinates)(const EC_GROUP *group, EC_POINT *p, BN_CTX *ctx);
    /*
        ladder_pre函数是椭圆曲线加密中的梯子算法(Ladder algorithm)中的初始化预计算步骤。
        其参数包含:
        const EC_GROUP *group: 椭圆曲线
        EC_POINT *r: 结果点
        EC_POINT *s: 临时辅助点
        EC_POINT *p: 固定参数点
        BN_CTX *ctx: BN变量空间
        梯子算法用于高效计算标量乘法 kP。该函数进行预计算:
        初始化结果点r和辅助点s
        计算固定参数点p的2倍点q = 2p
        预计算可以提高后续梯子步进运算的效率。
        函数返回1表示成功,0则失败,主要由于内存分配问题。
        该函数与ladder_step、ladder_post 一起实现梯子算法。预计算是首步。
    */
    int (*ladder_pre)(const EC_GROUP *group,
                      EC_POINT *r, EC_POINT *s,
                      EC_POINT *p, BN_CTX *ctx);
    /*
        ladder_step函数实现了椭圆曲线加密中梯子算法(Ladder algorithm)的主体步进逻辑。
        其参数包含:
        const EC_GROUP *group: 椭圆曲线
        EC_POINT *r: 结果点
        EC_POINT *s: 临时辅助点
        EC_POINT *p: 固定参数点
        BN_CTX *ctx: BN变量空间
        该函数会根据标量二进制位,选择性地进行点加减运算:
        当位为1时,执行 r = r + s, s = 2s
        当位为0时,执行 s = s + r, r = 2r
        依次迭代,可以高效计算标量乘法r = kP。
        它结合ladder_pre和ladder_post,实现整个梯子算法。
        返回1表示成功,0则失败,主要由于内存错误。
        梯子算法是计算椭圆曲线标量乘法的重要方法之一。
    */
    int (*ladder_step)(const EC_GROUP *group,
                       EC_POINT *r, EC_POINT *s,
                       EC_POINT *p, BN_CTX *ctx);
    /*
        ladder_post函数是椭圆曲线加密中梯子算法的后处理函数。
        其参数包含:
        const EC_GROUP *group: 椭圆曲线
        EC_POINT *r: 结果点
        EC_POINT *s: 临时辅助点
        EC_POINT *p: 固定参数点
        BN_CTX *ctx: BN变量空间
        在执行完梯子算法的主体步进运算后,需要进行后处理:
        检查辅助点s是否为无穷远点,如果不是,需要加回结果点r中。
        将结果点r中的z坐标设为1,转换到仿射坐标。
        这确保了最终的结果点r为准确的标量乘积kP结果。
        与ladder_pre和ladder_step一起,完成整个梯子算法。
        返回1成功,0失败,主要由内存错误造成。
        梯子算法需要合理设计预处理和后处理,以保证计算结果正确。
    */
    int (*ladder_post)(const EC_GROUP *group,
                       EC_POINT *r, EC_POINT *s,
                       EC_POINT *p, BN_CTX *ctx);
};

/*
 * Types and functions to manipulate pre-computed values.
 */
typedef struct nistp224_pre_comp_st NISTP224_PRE_COMP;
typedef struct nistp256_pre_comp_st NISTP256_PRE_COMP;
typedef struct nistp521_pre_comp_st NISTP521_PRE_COMP;
typedef struct nistz256_pre_comp_st NISTZ256_PRE_COMP;
typedef struct sm2p256_pre_comp_st SM2P256_PRE_COMP;
typedef struct sm2z256_pre_comp_st SM2Z256_PRE_COMP;
typedef struct ec_pre_comp_st EC_PRE_COMP;

struct ec_group_st {
    const EC_METHOD *meth;
    EC_POINT *generator;        /* optional */
    BIGNUM *order, *cofactor;
    int curve_name;             /* optional NID for named curve */
    int asn1_flag;              /* flag to control the asn1 encoding */
    int decoded_from_explicit_params; /* set if decoded from explicit
                                       * curve parameters encoding */
    point_conversion_form_t asn1_form;
    unsigned char *seed;        /* optional seed for parameters (appears in
                                 * ASN1) */
    size_t seed_len;
    /*
     * The following members are handled by the method functions, even if
     * they appear generic
     */
    /*
     * Field specification. For curves over GF(p), this is the modulus; for
     * curves over GF(2^m), this is the irreducible polynomial defining the
     * field.
     */
    BIGNUM *field;
    /*
     * Field specification for curves over GF(2^m). The irreducible f(t) is
     * then of the form: t^poly[0] + t^poly[1] + ... + t^poly[k] where m =
     * poly[0] > poly[1] > ... > poly[k] = 0. The array is terminated with
     * poly[k+1]=-1. All elliptic curve irreducibles have at most 5 non-zero
     * terms.
     */
    int poly[6];
    /*
     * Curve coefficients. (Here the assumption is that BIGNUMs can be used
     * or abused for all kinds of fields, not just GF(p).) For characteristic
     * > 3, the curve is defined by a Weierstrass equation of the form y^2 =
     * x^3 + a*x + b. For characteristic 2, the curve is defined by an
     * equation of the form y^2 + x*y = x^3 + a*x^2 + b.
     */
    BIGNUM *a, *b;
    /* enable optimized point arithmetics for special case */
    int a_is_minus3;
    /* method-specific (e.g., Montgomery structure) */
    void *field_data1;
    /* method-specific */
    void *field_data2;
    /* method-specific */
    int (*field_mod_func) (BIGNUM *, const BIGNUM *, const BIGNUM *,
                           BN_CTX *);
    /* data for ECDSA inverse */
    BN_MONT_CTX *mont_data;

    /*
     * Precomputed values for speed. The PCT_xxx names match the
     * pre_comp.xxx union names; see the SETPRECOMP and HAVEPRECOMP
     * macros, below.
     */
    enum {
        PCT_none,
        PCT_nistp224, PCT_nistp256, PCT_nistp521, PCT_nistz256, 
        PCT_sm2p256,
        PCT_sm2z256,
        PCT_ec
    } pre_comp_type;
    union {
        NISTP224_PRE_COMP *nistp224;
        NISTP256_PRE_COMP *nistp256;
        NISTP521_PRE_COMP *nistp521;
        NISTZ256_PRE_COMP *nistz256;
        SM2P256_PRE_COMP *sm2p256;
        SM2Z256_PRE_COMP *sm2z256;
        EC_PRE_COMP *ec;
    } pre_comp;

    OSSL_LIB_CTX *libctx;
    char *propq;
};

#define SETPRECOMP(g, type, pre) \
    g->pre_comp_type = PCT_##type, g->pre_comp.type = pre
#define HAVEPRECOMP(g, type) \
    g->pre_comp_type == PCT_##type && g->pre_comp.type != NULL

struct ec_key_st {
    const EC_KEY_METHOD *meth;
    ENGINE *engine;
    int version;
    EC_GROUP *group;
    EC_POINT *pub_key;
    BIGNUM *priv_key;
    unsigned int enc_flag;
    point_conversion_form_t conv_form;
    CRYPTO_REF_COUNT references;
    int flags;
#ifndef FIPS_MODULE
    CRYPTO_EX_DATA ex_data;
#endif
    CRYPTO_RWLOCK *lock;
    OSSL_LIB_CTX *libctx;
    char *propq;

    /* Provider data */
    size_t dirty_cnt; /* If any key material changes, increment this */
};

struct ec_point_st {
    const EC_METHOD *meth;
    /* NID for the curve if known */
    int curve_name;
    /*
     * All members except 'meth' are handled by the method functions, even if
     * they appear generic
     */
    BIGNUM *X;
    BIGNUM *Y;
    BIGNUM *Z;                  /* Jacobian projective coordinates: * (X, Y,
                                 * Z) represents (X/Z^2, Y/Z^3) if Z != 0 */
    int Z_is_one;               /* enable optimized point arithmetics for
                                 * special case */
};

static ossl_inline int ec_point_is_compat(const EC_POINT *point,
                                          const EC_GROUP *group)
{
    return group->meth == point->meth
           && (group->curve_name == 0
               || point->curve_name == 0
               || group->curve_name == point->curve_name);
}

NISTP224_PRE_COMP *EC_nistp224_pre_comp_dup(NISTP224_PRE_COMP *);
NISTP256_PRE_COMP *EC_nistp256_pre_comp_dup(NISTP256_PRE_COMP *);
NISTP521_PRE_COMP *EC_nistp521_pre_comp_dup(NISTP521_PRE_COMP *);
NISTZ256_PRE_COMP *EC_nistz256_pre_comp_dup(NISTZ256_PRE_COMP *);
NISTP256_PRE_COMP *EC_nistp256_pre_comp_dup(NISTP256_PRE_COMP *);
EC_PRE_COMP *EC_ec_pre_comp_dup(EC_PRE_COMP *);

void EC_pre_comp_free(EC_GROUP *group);
void EC_nistp224_pre_comp_free(NISTP224_PRE_COMP *);
void EC_nistp256_pre_comp_free(NISTP256_PRE_COMP *);
void EC_nistp521_pre_comp_free(NISTP521_PRE_COMP *);
void EC_nistz256_pre_comp_free(NISTZ256_PRE_COMP *);
void EC_ec_pre_comp_free(EC_PRE_COMP *);

/*
 * method functions in ec_mult.c (ec_lib.c uses these as defaults if
 * group->method->mul is 0)
 */
int ossl_ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                     size_t num, const EC_POINT *points[],
                     const BIGNUM *scalars[], BN_CTX *);
int ossl_ec_wNAF_precompute_mult(EC_GROUP *group, BN_CTX *);
int ossl_ec_wNAF_have_precompute_mult(const EC_GROUP *group);

/* method functions in ecp_smpl.c */
int ossl_ec_GFp_simple_group_init(EC_GROUP *);
void ossl_ec_GFp_simple_group_finish(EC_GROUP *);
void ossl_ec_GFp_simple_group_clear_finish(EC_GROUP *);
int ossl_ec_GFp_simple_group_copy(EC_GROUP *, const EC_GROUP *);
int ossl_ec_GFp_simple_group_set_curve(EC_GROUP *, const BIGNUM *p,
                                       const BIGNUM *a, const BIGNUM *b,
                                       BN_CTX *);
int ossl_ec_GFp_simple_group_get_curve(const EC_GROUP *, BIGNUM *p, BIGNUM *a,
                                       BIGNUM *b, BN_CTX *);
int ossl_ec_GFp_simple_group_get_degree(const EC_GROUP *);
int ossl_ec_GFp_simple_group_check_discriminant(const EC_GROUP *, BN_CTX *);
int ossl_ec_GFp_simple_point_init(EC_POINT *);
void ossl_ec_GFp_simple_point_finish(EC_POINT *);
void ossl_ec_GFp_simple_point_clear_finish(EC_POINT *);
int ossl_ec_GFp_simple_point_copy(EC_POINT *, const EC_POINT *);
int ossl_ec_GFp_simple_point_set_to_infinity(const EC_GROUP *, EC_POINT *);
int ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp(const EC_GROUP *,
                                                       EC_POINT *,
                                                       const BIGNUM *x,
                                                       const BIGNUM *y,
                                                       const BIGNUM *z,
                                                       BN_CTX *);
int ossl_ec_GFp_simple_get_Jprojective_coordinates_GFp(const EC_GROUP *,
                                                       const EC_POINT *,
                                                       BIGNUM *x,
                                                       BIGNUM *y, BIGNUM *z,
                                                       BN_CTX *);
int ossl_ec_GFp_simple_point_set_affine_coordinates(const EC_GROUP *, EC_POINT *,
                                                    const BIGNUM *x,
                                                    const BIGNUM *y, BN_CTX *);
int ossl_ec_GFp_simple_point_get_affine_coordinates(const EC_GROUP *,
                                                    const EC_POINT *, BIGNUM *x,
                                                    BIGNUM *y, BN_CTX *);
int ossl_ec_GFp_simple_set_compressed_coordinates(const EC_GROUP *, EC_POINT *,
                                                  const BIGNUM *x, int y_bit,
                                                  BN_CTX *);
size_t ossl_ec_GFp_simple_point2oct(const EC_GROUP *, const EC_POINT *,
                                    point_conversion_form_t form,
                                    unsigned char *buf, size_t len, BN_CTX *);
int ossl_ec_GFp_simple_oct2point(const EC_GROUP *, EC_POINT *,
                                 const unsigned char *buf, size_t len, BN_CTX *);
int ossl_ec_GFp_simple_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                           const EC_POINT *b, BN_CTX *);
int ossl_ec_GFp_simple_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                           BN_CTX *);
int ossl_ec_GFp_simple_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);
int ossl_ec_GFp_simple_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int ossl_ec_GFp_simple_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int ossl_ec_GFp_simple_cmp(const EC_GROUP *, const EC_POINT *a,
                           const EC_POINT *b, BN_CTX *);
int ossl_ec_GFp_simple_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int ossl_ec_GFp_simple_points_make_affine(const EC_GROUP *, size_t num,
                                          EC_POINT *[], BN_CTX *);
int ossl_ec_GFp_simple_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                                 const BIGNUM *b, BN_CTX *);
int ossl_ec_GFp_simple_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                                 BN_CTX *);
int ossl_ec_GFp_simple_field_inv(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                                 BN_CTX *);
int ossl_ec_GFp_simple_blind_coordinates(const EC_GROUP *group, EC_POINT *p,
                                         BN_CTX *ctx);
int ossl_ec_GFp_simple_ladder_pre(const EC_GROUP *group,
                                  EC_POINT *r, EC_POINT *s,
                                  EC_POINT *p, BN_CTX *ctx);
int ossl_ec_GFp_simple_ladder_step(const EC_GROUP *group,
                                   EC_POINT *r, EC_POINT *s,
                                   EC_POINT *p, BN_CTX *ctx);
int ossl_ec_GFp_simple_ladder_post(const EC_GROUP *group,
                                   EC_POINT *r, EC_POINT *s,
                                   EC_POINT *p, BN_CTX *ctx);

/* method functions in ecp_mont.c */
int ossl_ec_GFp_mont_group_init(EC_GROUP *);
int ossl_ec_GFp_mont_group_set_curve(EC_GROUP *, const BIGNUM *p,
                                     const BIGNUM *a,
                                     const BIGNUM *b, BN_CTX *);
void ossl_ec_GFp_mont_group_finish(EC_GROUP *);
void ossl_ec_GFp_mont_group_clear_finish(EC_GROUP *);
int ossl_ec_GFp_mont_group_copy(EC_GROUP *, const EC_GROUP *);
int ossl_ec_GFp_mont_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                               const BIGNUM *b, BN_CTX *);
int ossl_ec_GFp_mont_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                               BN_CTX *);
int ossl_ec_GFp_mont_field_inv(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                               BN_CTX *);
int ossl_ec_GFp_mont_field_encode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                                  BN_CTX *);
int ossl_ec_GFp_mont_field_decode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                                  BN_CTX *);
int ossl_ec_GFp_mont_field_set_to_one(const EC_GROUP *, BIGNUM *r, BN_CTX *);

/* method functions in ecp_nist.c */
int ossl_ec_GFp_nist_group_copy(EC_GROUP *dest, const EC_GROUP *src);
int ossl_ec_GFp_nist_group_set_curve(EC_GROUP *, const BIGNUM *p,
                                     const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int ossl_ec_GFp_nist_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                              const BIGNUM *b, BN_CTX *);
int ossl_ec_GFp_nist_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                               BN_CTX *);

/* method functions in ec2_smpl.c */
int ossl_ec_GF2m_simple_group_init(EC_GROUP *);
void ossl_ec_GF2m_simple_group_finish(EC_GROUP *);
void ossl_ec_GF2m_simple_group_clear_finish(EC_GROUP *);
int ossl_ec_GF2m_simple_group_copy(EC_GROUP *, const EC_GROUP *);
int ossl_ec_GF2m_simple_group_set_curve(EC_GROUP *, const BIGNUM *p,
                                        const BIGNUM *a, const BIGNUM *b,
                                        BN_CTX *);
int ossl_ec_GF2m_simple_group_get_curve(const EC_GROUP *, BIGNUM *p, BIGNUM *a,
                                        BIGNUM *b, BN_CTX *);
int ossl_ec_GF2m_simple_group_get_degree(const EC_GROUP *);
int ossl_ec_GF2m_simple_group_check_discriminant(const EC_GROUP *, BN_CTX *);
int ossl_ec_GF2m_simple_point_init(EC_POINT *);
void ossl_ec_GF2m_simple_point_finish(EC_POINT *);
void ossl_ec_GF2m_simple_point_clear_finish(EC_POINT *);
int ossl_ec_GF2m_simple_point_copy(EC_POINT *, const EC_POINT *);
int ossl_ec_GF2m_simple_point_set_to_infinity(const EC_GROUP *, EC_POINT *);
int ossl_ec_GF2m_simple_point_set_affine_coordinates(const EC_GROUP *,
                                                     EC_POINT *,
                                                     const BIGNUM *x,
                                                     const BIGNUM *y, BN_CTX *);
int ossl_ec_GF2m_simple_point_get_affine_coordinates(const EC_GROUP *,
                                                     const EC_POINT *, BIGNUM *x,
                                                     BIGNUM *y, BN_CTX *);
int ossl_ec_GF2m_simple_set_compressed_coordinates(const EC_GROUP *, EC_POINT *,
                                                   const BIGNUM *x, int y_bit,
                                                   BN_CTX *);
size_t ossl_ec_GF2m_simple_point2oct(const EC_GROUP *, const EC_POINT *,
                                     point_conversion_form_t form,
                                     unsigned char *buf, size_t len, BN_CTX *);
int ossl_ec_GF2m_simple_oct2point(const EC_GROUP *, EC_POINT *,
                                  const unsigned char *buf, size_t len, BN_CTX *);
int ossl_ec_GF2m_simple_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                            const EC_POINT *b, BN_CTX *);
int ossl_ec_GF2m_simple_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                            BN_CTX *);
int ossl_ec_GF2m_simple_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);
int ossl_ec_GF2m_simple_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int ossl_ec_GF2m_simple_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int ossl_ec_GF2m_simple_cmp(const EC_GROUP *, const EC_POINT *a,
                            const EC_POINT *b, BN_CTX *);
int ossl_ec_GF2m_simple_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int ossl_ec_GF2m_simple_points_make_affine(const EC_GROUP *, size_t num,
                                           EC_POINT *[], BN_CTX *);
int ossl_ec_GF2m_simple_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                                  const BIGNUM *b, BN_CTX *);
int ossl_ec_GF2m_simple_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                                  BN_CTX *);
int ossl_ec_GF2m_simple_field_div(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                                 const BIGNUM *b, BN_CTX *);

#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
# ifdef B_ENDIAN
#  error "Can not enable ec_nistp_64_gcc_128 on big-endian systems"
# endif

/* method functions in ecp_nistp224.c */
int ossl_ec_GFp_nistp224_group_init(EC_GROUP *group);
int ossl_ec_GFp_nistp224_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                         const BIGNUM *a, const BIGNUM *n,
                                         BN_CTX *);
int ossl_ec_GFp_nistp224_point_get_affine_coordinates(const EC_GROUP *group,
                                                      const EC_POINT *point,
                                                      BIGNUM *x, BIGNUM *y,
                                                      BN_CTX *ctx);
int ossl_ec_GFp_nistp224_mul(const EC_GROUP *group, EC_POINT *r,
                             const BIGNUM *scalar, size_t num,
                             const EC_POINT *points[], const BIGNUM *scalars[],
                             BN_CTX *);
int ossl_ec_GFp_nistp224_points_mul(const EC_GROUP *group, EC_POINT *r,
                                    const BIGNUM *scalar, size_t num,
                                    const EC_POINT *points[],
                                    const BIGNUM *scalars[], BN_CTX *ctx);
int ossl_ec_GFp_nistp224_precompute_mult(EC_GROUP *group, BN_CTX *ctx);
int ossl_ec_GFp_nistp224_have_precompute_mult(const EC_GROUP *group);

/* method functions in ecp_nistp256.c */
int ossl_ec_GFp_nistp256_group_init(EC_GROUP *group);
int ossl_ec_GFp_nistp256_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                         const BIGNUM *a, const BIGNUM *n,
                                         BN_CTX *);
int ossl_ec_GFp_nistp256_point_get_affine_coordinates(const EC_GROUP *group,
                                                      const EC_POINT *point,
                                                      BIGNUM *x, BIGNUM *y,
                                                      BN_CTX *ctx);
int ossl_ec_GFp_nistp256_mul(const EC_GROUP *group, EC_POINT *r,
                             const BIGNUM *scalar, size_t num,
                             const EC_POINT *points[], const BIGNUM *scalars[],
                             BN_CTX *);
int ossl_ec_GFp_nistp256_points_mul(const EC_GROUP *group, EC_POINT *r,
                                    const BIGNUM *scalar, size_t num,
                                    const EC_POINT *points[],
                                    const BIGNUM *scalars[], BN_CTX *ctx);
int ossl_ec_GFp_nistp256_precompute_mult(EC_GROUP *group, BN_CTX *ctx);
int ossl_ec_GFp_nistp256_have_precompute_mult(const EC_GROUP *group);

/* method functions in ecp_nistp521.c */
int ossl_ec_GFp_nistp521_group_init(EC_GROUP *group);
int ossl_ec_GFp_nistp521_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                         const BIGNUM *a, const BIGNUM *n,
                                         BN_CTX *);
int ossl_ec_GFp_nistp521_point_get_affine_coordinates(const EC_GROUP *group,
                                                      const EC_POINT *point,
                                                      BIGNUM *x, BIGNUM *y,
                                                      BN_CTX *ctx);
int ossl_ec_GFp_nistp521_mul(const EC_GROUP *group, EC_POINT *r,
                             const BIGNUM *scalar, size_t num,
                             const EC_POINT *points[], const BIGNUM *scalars[],
                             BN_CTX *);
int ossl_ec_GFp_nistp521_points_mul(const EC_GROUP *group, EC_POINT *r,
                                    const BIGNUM *scalar, size_t num,
                                    const EC_POINT *points[],
                                    const BIGNUM *scalars[], BN_CTX *ctx);
int ossl_ec_GFp_nistp521_precompute_mult(EC_GROUP *group, BN_CTX *ctx);
int ossl_ec_GFp_nistp521_have_precompute_mult(const EC_GROUP *group);

/* utility functions in ecp_nistputil.c */
void ossl_ec_GFp_nistp_points_make_affine_internal(size_t num, void *point_array,
                                                   size_t felem_size,
                                                   void *tmp_felems,
                                                   void (*felem_one) (void *out),
                                                   int (*felem_is_zero)
                                                       (const void *in),
                                                   void (*felem_assign)
                                                       (void *out, const void *in),
                                                   void (*felem_square)
                                                       (void *out, const void *in),
                                                   void (*felem_mul)
                                                       (void *out,
                                                        const void *in1,
                                                        const void *in2),
                                                   void (*felem_inv)
                                                       (void *out, const void *in),
                                                   void (*felem_contract)
                                                       (void *out, const void *in));
void ossl_ec_GFp_nistp_recode_scalar_bits(unsigned char *sign,
                                          unsigned char *digit,
                                          unsigned char in);
#endif
int ossl_ec_group_simple_order_bits(const EC_GROUP *group);

/**
 *  Creates a new EC_GROUP object
 *  \param   libctx The associated library context or NULL for the default
 *                  library context
 *  \param   propq  Any property query string
 *  \param   meth   EC_METHOD to use
 *  \return  newly created EC_GROUP object or NULL in case of an error.
 */
EC_GROUP *ossl_ec_group_new_ex(OSSL_LIB_CTX *libctx, const char *propq,
                               const EC_METHOD *meth);

#ifdef ECP_NISTZ256_ASM
/** Returns GFp methods using montgomery multiplication, with x86-64 optimized
 * P256. See http://eprint.iacr.org/2013/816.
 *  \return  EC_METHOD object
 */
const EC_METHOD *EC_GFp_nistz256_method(void);
#endif

#ifndef OPENSSL_NO_SM2
# if defined(ECP_NISTZ256_ASM) && BN_BITS2 == 64 && !defined(GMSSL_NO_TURBO)
const EC_METHOD *EC_GFp_sm2z256_method(void);
# endif
#endif

#ifdef S390X_EC_ASM
const EC_METHOD *EC_GFp_s390x_nistp256_method(void);
const EC_METHOD *EC_GFp_s390x_nistp384_method(void);
const EC_METHOD *EC_GFp_s390x_nistp521_method(void);
#endif

size_t ossl_ec_key_simple_priv2oct(const EC_KEY *eckey,
                                   unsigned char *buf, size_t len);
int ossl_ec_key_simple_oct2priv(EC_KEY *eckey, const unsigned char *buf,
                                size_t len);
int ossl_ec_key_simple_generate_key(EC_KEY *eckey);
int ossl_ec_key_simple_generate_public_key(EC_KEY *eckey);
int ossl_ec_key_simple_check_key(const EC_KEY *eckey);

int ossl_ec_curve_nid_from_params(const EC_GROUP *group, BN_CTX *ctx);

/* EC_METHOD definitions */

struct ec_key_method_st {
    const char *name;
    int32_t flags;
    int (*init)(EC_KEY *key);
    void (*finish)(EC_KEY *key);
    int (*copy)(EC_KEY *dest, const EC_KEY *src);
    int (*set_group)(EC_KEY *key, const EC_GROUP *grp);
    int (*set_private)(EC_KEY *key, const BIGNUM *priv_key);
    int (*set_public)(EC_KEY *key, const EC_POINT *pub_key);
    int (*keygen)(EC_KEY *key);
    int (*compute_key)(unsigned char **pout, size_t *poutlen,
                       const EC_POINT *pub_key, const EC_KEY *ecdh);
    int (*sign)(int type, const unsigned char *dgst, int dlen, unsigned char
                *sig, unsigned int *siglen, const BIGNUM *kinv,
                const BIGNUM *r, EC_KEY *eckey);
    int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                      BIGNUM **rp);
    ECDSA_SIG *(*sign_sig)(const unsigned char *dgst, int dgst_len,
                           const BIGNUM *in_kinv, const BIGNUM *in_r,
                           EC_KEY *eckey);

    int (*verify)(int type, const unsigned char *dgst, int dgst_len,
                  const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);
    int (*verify_sig)(const unsigned char *dgst, int dgst_len,
                      const ECDSA_SIG *sig, EC_KEY *eckey);
};

#define EC_KEY_METHOD_DYNAMIC   1

EC_KEY *ossl_ec_key_new_method_int(OSSL_LIB_CTX *libctx, const char *propq,
                                   ENGINE *engine);

int ossl_ec_key_gen(EC_KEY *eckey);
int ossl_ecdh_compute_key(unsigned char **pout, size_t *poutlen,
                          const EC_POINT *pub_key, const EC_KEY *ecdh);
int ossl_ecdh_simple_compute_key(unsigned char **pout, size_t *poutlen,
                                 const EC_POINT *pub_key, const EC_KEY *ecdh);

struct ECDSA_SIG_st {
    BIGNUM *r;
    BIGNUM *s;
};

int ossl_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                          BIGNUM **rp);
int ossl_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                    unsigned char *sig, unsigned int *siglen,
                    const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);
ECDSA_SIG *ossl_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len,
                               const BIGNUM *in_kinv, const BIGNUM *in_r,
                               EC_KEY *eckey);
int ossl_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                      const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);
int ossl_ecdsa_verify_sig(const unsigned char *dgst, int dgst_len,
                          const ECDSA_SIG *sig, EC_KEY *eckey);
int ossl_ecdsa_simple_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                                 BIGNUM **rp);
ECDSA_SIG *ossl_ecdsa_simple_sign_sig(const unsigned char *dgst, int dgst_len,
                                      const BIGNUM *in_kinv, const BIGNUM *in_r,
                                      EC_KEY *eckey);
int ossl_ecdsa_simple_verify_sig(const unsigned char *dgst, int dgst_len,
                                 const ECDSA_SIG *sig, EC_KEY *eckey);


/*-
 * This functions computes a single point multiplication over the EC group,
 * using, at a high level, a Montgomery ladder with conditional swaps, with
 * various timing attack defenses.
 *
 * It performs either a fixed point multiplication
 *          (scalar * generator)
 * when point is NULL, or a variable point multiplication
 *          (scalar * point)
 * when point is not NULL.
 *
 * `scalar` cannot be NULL and should be in the range [0,n) otherwise all
 * constant time bets are off (where n is the cardinality of the EC group).
 *
 * This function expects `group->order` and `group->cardinality` to be well
 * defined and non-zero: it fails with an error code otherwise.
 *
 * NB: This says nothing about the constant-timeness of the ladder step
 * implementation (i.e., the default implementation is based on EC_POINT_add and
 * EC_POINT_dbl, which of course are not constant time themselves) or the
 * underlying multiprecision arithmetic.
 *
 * The product is stored in `r`.
 *
 * This is an internal function: callers are in charge of ensuring that the
 * input parameters `group`, `r`, `scalar` and `ctx` are not NULL.
 *
 * Returns 1 on success, 0 otherwise.
 */
int ossl_ec_scalar_mul_ladder(const EC_GROUP *group, EC_POINT *r,
                              const BIGNUM *scalar, const EC_POINT *point,
                              BN_CTX *ctx);

int ossl_ec_point_blind_coordinates(const EC_GROUP *group, EC_POINT *p,
                                    BN_CTX *ctx);

static ossl_inline int ec_point_ladder_pre(const EC_GROUP *group,
                                           EC_POINT *r, EC_POINT *s,
                                           EC_POINT *p, BN_CTX *ctx)
{
    if (group->meth->ladder_pre != NULL)
        return group->meth->ladder_pre(group, r, s, p, ctx);

    if (!EC_POINT_copy(s, p)
        || !EC_POINT_dbl(group, r, s, ctx))
        return 0;

    return 1;
}

static ossl_inline int ec_point_ladder_step(const EC_GROUP *group,
                                            EC_POINT *r, EC_POINT *s,
                                            EC_POINT *p, BN_CTX *ctx)
{
    if (group->meth->ladder_step != NULL)
        return group->meth->ladder_step(group, r, s, p, ctx);

    if (!EC_POINT_add(group, s, r, s, ctx)
        || !EC_POINT_dbl(group, r, r, ctx))
        return 0;

    return 1;

}

static ossl_inline int ec_point_ladder_post(const EC_GROUP *group,
                                            EC_POINT *r, EC_POINT *s,
                                            EC_POINT *p, BN_CTX *ctx)
{
    if (group->meth->ladder_post != NULL)
        return group->meth->ladder_post(group, r, s, p, ctx);

    return 1;
}
