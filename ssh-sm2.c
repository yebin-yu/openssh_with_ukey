#include "includes.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <string.h>
#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#include "sshkey.h"
#include "skfapi.h"

#include "openbsd-compat/openssl-compat.h"

/* Reuse some ECDSA internals */
extern struct sshkey_impl_funcs sshkey_ecdsa_funcs;

const unsigned char *sm2_id = (const unsigned char *)"1234567812345678";

static void
ssh_sm2_cleanup(struct sshkey *k)
{
	EC_KEY_free(k->ecdsa);
	k->ecdsa = NULL;
}

static int
ssh_sm2_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (!sshkey_ecdsa_funcs.equal(a, b))
		return 0;
	return 1;
}

static int
ssh_sm2_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if ((r = sshkey_ecdsa_funcs.serialize_public(key, b, opts)) != 0)
		return r;

	return 0;
}

static int
ssh_sm2_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;

	if ((r = sshkey_ecdsa_funcs.deserialize_public(ktype, b, key)) != 0)
		return r;
	return 0;
}

static int
ssh_sm2_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if ((r = sshkey_ecdsa_funcs.serialize_private(key, b, opts)) != 0)
		return r;

	return 0;
}

static int
ssh_sm2_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;

	if ((r = sshkey_ecdsa_funcs.deserialize_private(ktype, b, key)) != 0)
		return r;

	return 0;
}

static int
ssh_sm2_generate(struct sshkey *k, int bits)
{
	EC_KEY *private;

	k->ecdsa_nid = NID_sm2;
	if ((private = EC_KEY_new_by_curve_name(k->ecdsa_nid)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (EC_KEY_generate_key(private) != 1) {
		EC_KEY_free(private);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	EC_KEY_set_asn1_flag(private, OPENSSL_EC_NAMED_CURVE);
	k->ecdsa = private;
	return 0;
}

static int
ssh_sm2_copy_public(const struct sshkey *from, struct sshkey *to)
{
	int r;

	if ((r = sshkey_ecdsa_funcs.copy_public(from, to)) != 0)
		return r;
	return 0;
}

static int
sm2_get_sig(EVP_PKEY *pkey, const u_char *data,
    size_t datalen, u_char *sig, size_t *slen)
{
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX *mctx = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if ((pctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((mctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_CTX_set1_id(pctx, sm2_id, 16) != 1) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	EVP_MD_CTX_set_pkey_ctx(mctx, pctx);

	if ((EVP_DigestSignInit(mctx, NULL, EVP_sm3(), NULL, pkey)) != 1) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if ((EVP_DigestSignUpdate(mctx, data, datalen)) != 1) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if ((EVP_DigestSignFinal(mctx, sig, slen)) != 1) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	ret = 0;

out:
	EVP_PKEY_CTX_free(pctx);
	EVP_MD_CTX_free(mctx);
	return ret;
}

static void dumpBytesHex(const char *name, unsigned char *bytes, size_t bytesLen)
{
    const char *outName = (name != NULL) ? name : "Default:";
    printf("%s", outName);

    for (int i = 0; i < bytesLen; i++) {
        printf("%x", bytes[i]);
    }

    printf("\n");
}

static int
ukey_get_sig(const u_char *data, size_t datalen, u_char *sig, size_t *slen)
{
    HANDLE hdev = NULL;
    ULONG ulRslt = SAR_OK;

    // 枚举获取设备名，这里的逻辑应该是自动获取然后赋值
	// ukey上获取到的值应该为：3DC2105010CFD4C62A42E5375DA38B9
    char szDevName[256] = {0}; 
    ULONG ulDevNameLen = 256;
    ulRslt = SKF_EnumDev(TRUE, szDevName, &ulDevNameLen);
    printf("szDevName: %s", szDevName);
    NOT_OK_THROW(ulRslt, "SKF_EnumDev error");

    // 连接设备
    sleep(2);
    ulRslt = SKF_ConnectDev(szDevName, &hdev);
    NOT_OK_THROW(ulRslt, "SKF_ConnectDev error");

    // 获取application，这里的逻辑应该是自动获取然后赋值
	// ukey上获取到的值应该为：GM3000RSA
    char appName[256] = {0}; 
    ULONG appnameLen = 256;
    ulRslt = SKF_EnumApplication(hdev, appName, &appnameLen);
    printf("appName: %s", appName);
    NOT_OK_THROW(ulRslt, "SKF_EnumApplication error");

    // 打开应用
    HANDLE happ;
    ulRslt = SKF_OpenApplication(hdev, appName, &happ);
    NOT_OK_THROW(ulRslt, "SKF_OpenApplication error");

    // 验证pin码
    char pinStr[32];
    ULONG retryCnt = 15;
    printf("UKEY pin:");
    scanf("%s", pinStr);
    ulRslt = SKF_VerifyPIN(happ, USER_TYPE, pinStr, &retryCnt);
    NOT_OK_THROW(ulRslt, "SKF_VerifyPIN error");

    // 获取容器名
	// ukey上获取到的值应该为：sm2
    char containerName[256] = {0};
    ULONG containerNameLen = 256;
    ulRslt = SKF_EnumContainer(happ, containerName, &containerNameLen);
    printf("containerName: %s", containerName);
    NOT_OK_THROW(ulRslt, "SKF_EnumContainer error");

    // 打开容器
    HANDLE hcontainer;
    ulRslt = SKF_OpenContainer(happ, containerName, &hcontainer);
    NOT_OK_THROW(ulRslt, "SKF_OpenContainer error");

    // 导出公钥 -> 签名的时候不需要
    // BYTE buf[512] = {0};
    // ULONG bufLen = sizeof(buf);
    // ulRslt = SKF_ExportPublicKey(hcontainer, TRUE, buf, &bufLen);
    // NOT_OK_THROW(ulRslt, "SKF_ExportPublicKey error");

    // ECCPUBLICKEYBLOB *blob = (ECCPUBLICKEYBLOB *)buf;
    // FILE *fp = fopen("pub.gm", "wb");
    // fwrite(blob, sizeof(BYTE), sizeof(ECCPUBLICKEYBLOB), fp);
    // fclose(fp);

    // 尝试签名
	// FIXME: 签名需要的是hcontainer，是否需要每次都重新获取？
	//        可以在创建ssh连接的时候就保存container
    ECCSIGNATUREBLOB stSign = {0};
    BYTE data_byte[datalen];
	for (int i = 0; i < strlen(datalen); i++) {
    	data_byte[i] = (byte)data[i];
	}

    ulRslt = SKF_ECCSignData(hcontainer, data_byte, 32, &stSign);
    NOT_OK_THROW(ulRslt, "SKF_ECCSignData");

    // 保存签名文件
    fp = fopen("sig.gm", "wb");
    fwrite(&stSign, sizeof(BYTE), sizeof(ECCSIGNATUREBLOB), fp);
    fclose(fp);

	fp = fopen("sig.gm", "r");
	size_t n = fread(sig, 1, sizeof(ECCSIGNATUREBLOB), fp);
	fclose(fp);

	// 打印看公钥和签名信息 -> 需要删除
    dumpBytesHex("x: ", blob->XCoordinate, sizeof(blob->XCoordinate));
    dumpBytesHex("y: ", blob->YCoordinate, sizeof(blob->YCoordinate));

    dumpBytesHex("r: ", stSign.r, sizeof(stSign.r));
    dumpBytesHex("s: ", stSign.s, sizeof(stSign.s));

    // 验证签名 -> 这里也不需要
    // ulRslt = SKF_ECCVerify(hdev, blob, data, 32, &stSign);
    // NOT_OK_THROW(ulRslt, "SKF_ECCVerify");

END_OF_FUN:
    SKF_DisConnectDev(hdev);
    return 1;
}

static int
ssh_sm2_sign_new(struct sshkey *key,
   u_char **sigp, size_t *lenp,
   const u_char *data, size_t datalen,
   const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	u_char *sig = NULL;
	int pkey_len = 0;
	int r = 0;
	int len = 0;
	EVP_PKEY *key_sm2 = NULL;
	struct sshbuf *b = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->ecdsa == NULL ||
		sshkey_type_plain(key->type) != KEY_SM2)
		return SSH_ERR_INVALID_ARGUMENT;

	// 初始化key_sm2，获取最终签名的长度，得修改。
	// 【签名部分】获取sig，也就是签名内容，内容在sig中
	size_t slen = sizeof(ECCSIGNATUREBLOB);
	if ((sig = OPENSSL_malloc(sizeof(ECCSIGNATUREBLOB))) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (ret = ukey_get_sig(data, datalen, sig, &slen)) {
		goto out;
	}
    
	// 把签名内容存在b中
	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_cstring(b, "sm2")) != 0 ||
		(r = sshbuf_put_string(b, sig, slen)) != 0)
		goto out;
	
	// 把签名存到b中，再把b拷贝到*sigp中
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
			*lenp = len;
	ret = 0;

out:
	EVP_PKEY_free(key_sm2);
	if (sig != NULL) {
		explicit_bzero(sig, slen);
		OPENSSL_free(sig);
	}
	sshbuf_free(b);
	return ret;
}

static int
ssh_sm2_sign(struct sshkey *key,
   u_char **sigp, size_t *lenp,
   const u_char *data, size_t datalen,
   const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	u_char *sig = NULL;
	size_t slen = 0;
	int pkey_len = 0;
	int r = 0;
	int len = 0;
	EVP_PKEY *key_sm2 = NULL;
	struct sshbuf *b = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->ecdsa == NULL ||
		sshkey_type_plain(key->type) != KEY_SM2)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((key_sm2 = EVP_PKEY_new()) == NULL) {
		return SSH_ERR_ALLOC_FAIL;
	}

	if ((EVP_PKEY_set1_EC_KEY(key_sm2, key->ecdsa)) != 1) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if ((pkey_len = EVP_PKEY_size(key_sm2)) == 0) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	slen = pkey_len;

	if ((sig = OPENSSL_malloc(pkey_len)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (ret = sm2_get_sig(key_sm2, data, datalen, sig, &slen)) {
		goto out;
	}

	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = sshbuf_put_cstring(b, "sm2")) != 0 ||
		(r = sshbuf_put_string(b, sig, slen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
			*lenp = len;
	ret = 0;

out:
	EVP_PKEY_free(key_sm2);
	if (sig != NULL) {
		explicit_bzero(sig, slen);
		OPENSSL_free(sig);
	}
	sshbuf_free(b);
	return ret;
}

static int
sm2_verify_sig(EVP_PKEY *pkey, const u_char *data,
    size_t datalen, const u_char *sig, size_t slen)
{
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX *mctx = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if ((pctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((mctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (EVP_PKEY_CTX_set1_id(pctx, sm2_id, 16) != 1) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	EVP_MD_CTX_set_pkey_ctx(mctx, pctx);

	if ((EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey)) != 1) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if ((EVP_DigestVerifyUpdate(mctx, data, datalen)) != 1) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if ((EVP_DigestVerifyFinal(mctx, sig, slen)) != 1) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	ret = 0;
out:
	EVP_PKEY_CTX_free(pctx);
	EVP_MD_CTX_free(mctx);
	return ret;
}

static int
ssh_sm2_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	const u_char *sig = NULL;
	char *ktype = NULL;
	size_t slen = 0;
	int pkey_len = 0;
	int r = 0;
	int len = 0;
	EVP_PKEY *key_sm2 = NULL;
	struct sshbuf *b = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_SM2 ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((b = sshbuf_from(signature, signaturelen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((r = sshbuf_get_cstring(b, &ktype, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sig, &slen)) != 0)
		goto out;

	if (strcmp("sm2", ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	if ((key_sm2 = EVP_PKEY_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((EVP_PKEY_set1_EC_KEY(key_sm2, key->ecdsa)) != 1) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if ((pkey_len = EVP_PKEY_size(key_sm2)) == 0) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	if (ret = sm2_verify_sig(key_sm2, data, datalen, sig, slen)) {
		goto out;
	}

	ret = 0;
out:
	EVP_PKEY_free(key_sm2);
	sshbuf_free(b);
	free(ktype);
	return ret;
}

static const struct sshkey_impl_funcs sshkey_sm2_funcs = {
	/* .size = */		NULL,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_sm2_cleanup,
	/* .equal = */		ssh_sm2_equal,
	/* .ssh_serialize_public = */	ssh_sm2_serialize_public,
	/* .ssh_deserialize_public = */ ssh_sm2_deserialize_public,
	/* .ssh_serialize_private = */	ssh_sm2_serialize_private,
	/* .ssh_deserialize_private = */ssh_sm2_deserialize_private,
	/* .generate = */	ssh_sm2_generate,
	/* .copy_public = */	ssh_sm2_copy_public,
	/* .sign = */		ssh_sm2_sign,
	/* .verify = */		ssh_sm2_verify,
};

const struct sshkey_impl sshkey_sm2_impl = {
	/* .name = */		"sm2",
	/* .shortname = */	"SM2",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_SM2,
	/* .nid = */		NID_sm2,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_sm2_funcs,
};

const struct sshkey_impl sshkey_sm2_cert_impl = {
	/* .name = */		"sm2-cert",
	/* .shortname = */	"SM2-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_SM2_CERT,
	/* .nid = */		NID_sm2,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_sm2_funcs,
};
