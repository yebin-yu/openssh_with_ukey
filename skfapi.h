
#ifndef _SKFAPI_H_
#define _SKFAPI_H_

#pragma pack(1)

#define SAR_OK							0x00000000	//�ɹ�
#define SAR_FAIL						0x0A000001	//ʧ��
#define SAR_UNKNOWNERR					0x0A000002	//�쳣����
#define SAR_NOTSUPPORTYETERR			0x0A000003	//��֧�ֵķ���
#define SAR_FILEERR						0x0A000004	//�ļ���������
#define SAR_INVALIDHANDLEERR			0x0A000005	//��Ч�ľ��
#define SAR_INVALIDPARAMERR				0x0A000006	//��Ч�Ĳ���
#define SAR_READFILEERR					0x0A000007	//���ļ�����
#define SAR_WRITEFILEERR				0x0A000008	//д�ļ�����
#define SAR_NAMELENERR					0x0A000009	//���Ƴ��ȴ���
#define SAR_KEYUSAGEERR					0x0A00000A	//��Կ��;����
#define SAR_MODULUSLENERR				0x0A00000B	//ģ�ĳ��ȴ���
#define SAR_NOTINITIALIZEERR 			0x0A00000C	//δ��ʼ��
#define SAR_OBJERR						0x0A00000D	//�������
#define SAR_MEMORYERR					0x0A00000E	//�ڴ����
#define SAR_TIMEOUTERR					0x0A00000F	//��ʱ
#define SAR_INDATALENERR				0x0A000010	//�������ݳ��ȴ���
#define SAR_INDATAERR					0x0A000011	//�������ݴ���
#define SAR_GENRANDERR					0x0A000012	//�������������
#define SAR_HASHOBJERR					0x0A000013	//HASH�������
#define SAR_HASHERR						0x0A000014	//HASH�������
#define SAR_GENRSAKEYERR				0x0A000015	//����RSA��Կ����
#define SAR_RSAMODULUSLENERR			0x0A000016	//RSA��Կģ������
#define SAR_CSPIMPRTPUBKEYERR			0x0A000017	//CSP�����빫Կ����
#define SAR_RSAENCERR					0x0A000018	//RSA���ܴ���
#define SAR_RSADECERR					0x0A000019	//RSA���ܴ���
#define SAR_HASHNOTEQUALERR				0x0A00001A	//HASHֵ�����
#define SAR_KEYNOTFOUNTERR				0x0A00001B	//δ������Կ
#define SAR_CERTNOTFOUNTERR				0x0A00001C	//δ����֤��
#define SAR_NOTEXPORTERR				0x0A00001D	//����δ����
#define SAR_DECRYPTPADERR				0x0A00001E	//����ʱ����������
#define SAR_MACLENERR					0x0A00001F	//MAC���ȴ���
#define SAR_BUFFER_TOO_SMALL			0x0A000020	//����������
#define SAR_KEYINFOTYPEERR				0x0A000021	//��Կ���ʹ���
#define SAR_NOT_EVENTERR				0x0A000022	//���¼�����
#define SAR_DEVICE_REMOVED				0x0A000023	//�豸���Ƴ�
#define SAR_PIN_INCORRECT				0x0A000024	//PIN����
#define SAR_PIN_LOCKED					0x0A000025	//PIN����
#define SAR_PIN_INVALID					0x0A000026	//PIN��Ч
#define SAR_PIN_LEN_RANGE				0x0A000027	//PIN���ȴ���
#define SAR_USER_ALREADY_LOGGED_IN		0x0A000028	//�û��Ѿ���¼
#define SAR_USER_PIN_NOT_INITIALIZED	0x0A000029	//û�г�ʼ���û�����
#define SAR_USER_TYPE_INVALID			0x0A00002A	//PIN���ʹ���
#define SAR_APPLICATION_NAME_INVALID	0x0A00002B	//Ӧ��������Ч
#define SAR_APPLICATION_EXISTS			0x0A00002C	//Ӧ���Ѿ�����
#define SAR_USER_NOT_LOGGED_IN			0x0A00002D	//�û�û�е�¼
#define SAR_APPLICATION_NOT_EXISTS		0x0A00002E	//Ӧ�ò�����
#define SAR_FILE_ALREADY_EXIST			0x0A00002F	//�ļ��Ѿ�����
#define SAR_NO_ROOM						0x0A000030	//�洢�ռ䲻��
#define SAR_FILE_NOT_EXIST				0x0A000031	//�ļ�������
#define SAR_REACH_MAX_CONTAINER_COUNT	0x0A000032	//�Ѵﵽ���ɹ���������

#define SAR_SECURITY_INVALID			0x0B000033	//��ȫ״̬������
#define SAR_OFFSET_VOER_FILE			0x0B000034	//ָ���Ƶ������ļ�����
#define SAR_CONTAINER_NOT_FOUND			0x0B000035	//����������
#define SAR_CONTAINER_EXIST				0x0B000036	//�����Ѵ���
#define SAR_AUTH_LOCKED					0x0B000037	//�豸��֤����
#define SAR_ECCENCERR					0x0B000038	//ECC���ܴ���

#ifdef WIN32
#define DEVAPI  __stdcall
#else
#define DEVAPI
#endif


#ifdef __cplusplus
extern "C" {
#endif


	typedef signed char         INT8;
	typedef signed short        INT16;
	typedef signed int          INT32;
	typedef unsigned char       UINT8;
	typedef unsigned short      UINT16;
	typedef unsigned int	    UINT32;

	typedef UINT8				BYTE;
	typedef char				CHAR;
	typedef INT16				SHORT;
	typedef UINT16				USHORT;
	typedef long				LONG;
#ifdef WIN32
	typedef unsigned long		ULONG;
#else
	typedef unsigned int		ULONG;				
#endif
	typedef UINT32				UINT;
	typedef UINT16				WORD;
	typedef unsigned long		DWORD;
	typedef UINT32				FLAGS;
	typedef CHAR *				LPSTR;
	typedef void *				HANDLE;
	typedef int					BOOL;

	typedef HANDLE				DEVHANDLE;
	typedef HANDLE				HAPPLICATION;
	typedef HANDLE				HCONTAINER;

#define MAX_IV_LEN						32	//��ʼ����������󳤶�
#define	MAX_FILE_NAME_LEN				32	//�ļ�����󳤶�
//#define MAX_CONTAINER_NAME_LEN			128	//��������󳤶�
#define MIN_PIN_LEN						6	//��С��PIN����

#define MAX_RSA_MODULUS_LEN				256	//RSA�㷨ģ������󳤶�
#define MAX_RSA_EXPONENT_LEN			4	//RSA�㷨ָ������󳤶�

#define ECC_MAX_XCOORDINATE_BITS_LEN	512	//ECC�㷨X�������󳤶�
#define ECC_MAX_YCOORDINATE_BITS_LEN	512	//ECC�㷨Y�������󳤶�
#define ECC_MAX_MODULUS_BITS_LEN		512	//ECC�㷨ģ������󳤶�


#define SGD_SM1_ECB				0x00000101	//SM1�㷨ECB����ģʽ
#define SGD_SM1_CBC				0x00000102	//SM1�㷨CBC����ģʽ
#define SGD_SM1_CFB				0x00000104	//SM1�㷨CFB����ģʽ
#define SGD_SM1_OFB				0x00000108	//SM1�㷨OFB����ģʽ
#define SGD_SM1_MAC				0x00000110	//SM1�㷨MAC����
#define SGD_SSF33_ECB			0x00000201	//SSF33�㷨ECB����ģʽ
#define SGD_SSF33_CBC			0x00000202	//SSF33�㷨CBC����ģʽ
#define SGD_SSF33_CFB			0x00000204	//SSF33�㷨CFB����ģʽ
#define SGD_SSF33_OFB			0x00000208	//SSF33�㷨OFB����ģʽ
#define SGD_SSF33_MAC			0x00000210	//SSF33�㷨MAC����
#define SGD_SM4_ECB				0x00000401	//SMS4�㷨ECB����ģʽ
#define SGD_SM4_CBC				0x00000402	//SMS4�㷨CBC����ģʽ
#define SGD_SM4_CFB				0x00000404	//SMS4�㷨CFB����ģʽ
#define SGD_SM4_OFB				0x00000408	//SMS4�㷨OFB����ģʽ
#define SGD_SM4_MAC				0x00000410	//SMS4�㷨MAC����

//�ǶԳ������㷨��ʶ
#define SGD_RSA					0x00010000	//RSA�㷨
#define SGD_SM2_1				0x00020100	//��Բ����ǩ���㷨
#define SGD_SM2_2				0x00020200	//��Բ������Կ����Э��
#define SGD_SM2_3				0x00020400	//��Բ���߼����㷨

//�����Ӵ��㷨��ʶ
#define SGD_SM3					0x00000001	//SM3�Ӵ��㷨
#define SGD_SHA1				0x00000002	//SHA1�Ӵ��㷨
#define SGD_SHA256				0x00000004	//SHA256�Ӵ��㷨

//�豸״̬
#define	DEV_ABSENT_STATE		0x00000000	//�豸������
#define	DEV_PRESENT_STATE		0x00000001	//�豸����
#define DEV_UNKNOW_STATE        0x00000002   //�豸״̬δ֪

//�豸Ȩ��
#define SECURE_NEVER_ACCOUNT	0x00000000	//������
#define SECURE_ADM_ACCOUNT		0x00000001	//����ԱȨ��
#define SECURE_USER_ACCOUNT		0x00000010	//�û�Ȩ��
#define SECURE_EVERYONE_ACCOUNT	0x000000FF	//�κ���


//PIN������
#define	ADMIN_TYPE				0x00000000	// ����ԱPIN
#define USER_TYPE				0x00000001	// �û�PIN

typedef struct Struct_Version{
	BYTE	major;	//���汾��
	BYTE	minor;	//�ΰ汾��
} VERSION;


typedef struct Struct_DEVINFO{
	VERSION		Version;
	CHAR		Manufacturer[64];
	CHAR		Issuer[64];
	CHAR		Label[32];
	CHAR		SerialNumber[32];
	VERSION		HWVersion;
	VERSION		FirmwareVersion;
	ULONG		AlgSymCap;
	ULONG		AlgAsymCap;
	ULONG		AlgHashCap;
	ULONG		DevAuthAlgId;
	ULONG		TotalSpace;
	ULONG		FreeSpace;
	ULONG		MaxECCBufferSize;
	ULONG		MaxBufferSize;
	BYTE  		Reserved[64];
}DEVINFO,*PDEVINFO;


//RSA��Կ�������ݿ�
typedef struct Struct_RSAPUBLICKEYBLOB{
	ULONG	AlgID;									//�㷨��ʶ��
	ULONG	BitLen;									//ģ����ʵ��λ���ȣ�������8�ı���
	BYTE	Modulus[MAX_RSA_MODULUS_LEN];			//ģ��n=p*q��ʵ�ʳ���ΪBitLen/8�ֽ�
	BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];	//������Կe�� һ��Ϊ00010001
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;


//RSA˽Կ�������ݿ�
typedef struct Struct_RSAPRIVATEKEYBLOB{
	ULONG	AlgID;									//�㷨��ʶ��
	ULONG	BitLen;									//ģ����ʵ��λ���ȣ�������8�ı���
	BYTE	Modulus[MAX_RSA_MODULUS_LEN];			//ģ��n=p*q��ʵ�ʳ���ΪBitLen/8�ֽ�
	BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];	//������Կe�� һ��Ϊ00010001
	BYTE	PrivateExponent[MAX_RSA_MODULUS_LEN];	//˽����Կd��ʵ�ʳ���ΪBitLen/8�ֽ�
	BYTE	Prime1[MAX_RSA_MODULUS_LEN/2];			//����p��ʵ�ʳ���ΪBitLen/16�ֽ�
	BYTE	Prime2[MAX_RSA_MODULUS_LEN/2];			//����q��ʵ�ʳ���ΪBitLen/16�ֽ�
	BYTE	Prime1Exponent[MAX_RSA_MODULUS_LEN/2];	//d mod (p-1)��ֵ, ʵ�ʳ���ΪBitLen/16�ֽ�
	BYTE	Prime2Exponent[MAX_RSA_MODULUS_LEN/2];	//d mod (q-1)��ֵ��ʵ�ʳ���ΪBitLen/16�ֽ�
	BYTE	Coefficient[MAX_RSA_MODULUS_LEN/2];		//qģp�ĳ˷���Ԫ��ʵ�ʳ���ΪBitLen/16�ֽ�
} RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

//ECC��Կ�������ݿ�
typedef struct Struct_ECCPUBLICKEYBLOB{
	ULONG	BitLen;
	BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;


//ECC˽Կ�������ݿ�
typedef struct Struct_ECCPRIVATEKEYBLOB{
	ULONG	BitLen;
	BYTE	PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];
}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;



// ECC�������ݽṹ
typedef struct Struct_ECCCIPHERBLOB{
	BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	BYTE	YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	BYTE	HASH[32];
	UINT32	CipherLen;
	BYTE	Cipher[1];
} ECCCIPHERBLOB, *PECCCIPHERBLOB;


// ECCǩ�����ݽṹ
typedef struct Struct_ECCSIGNATUREBLOB{
	BYTE	r[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE	s[ECC_MAX_YCOORDINATE_BITS_LEN/8];
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

//ECC������Կ�Ա����ṹ
typedef struct Struct_ENVELOPEDKEYBLOB{
	UINT32 Version;                  // ��ǰ�汾Ϊ 1
	UINT32 ulSymmAlgID;              // �淶�е��㷨��ʶ���޶�ECBģʽ
	UINT32 ulBits;					// ������Կ�Ե���Կλ����
	BYTE cbEncryptedPriKey[64];     // ���ܱ����ļ���˽Կ
	ECCPUBLICKEYBLOB PubKey;        // ���ܹ�Կ
	ECCCIPHERBLOB ECCCipherBlob;    // SM2 ��Կ���ܵ���Կ������Կ
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
typedef struct Struct_BLOCKCIPHERPARAM{
	BYTE	IV[MAX_IV_LEN];			//��ʼ������MAX_IV_LENΪ��ʼ��������󳤶�
	ULONG	IVLen;					//��ʼ����ʵ�ʳ��ȣ����ֽڼ���
	ULONG	PaddingType;			//��䷽ʽ��0��ʾ����䣬1��ʾ����PKCS#5��ʽ�������
	ULONG	FeedBitLen;				//����ֵ��λ���ȣ����ֽڼ��㣬ֻ���OFB��CFBģʽ
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

// �ļ�����
typedef struct Struct_FILEATTRIBUTE{
	CHAR	FileName[32];
	ULONG	FileSize;
	ULONG	ReadRights;
	ULONG	WriteRights; 
}FILEATTRIBUTE, *PFILEATTRIBUTE;

#pragma pack()
/************************************************************************/
/*	1. �豸����	ϵ�к���														*/
/*	SKF_WaitForDevEvent													*/
/*	SKF_CancelWaitForDevEvent											*/
/*	SKF_EnumDev															*/
/*	SKF_ConnectDev														*/
/*	SKF_DisconnectDev													*/
/*	SKF_GetDevState														*/
/*	SKF_SetLable														*/
/*	SKF_GetDevInfo														*/
/*	SKF_LockDev															*/
/*	SKF_UnlockDev														*/
/*	SKF_Transmit														*/
/************************************************************************/

/*
*	�ȴ��豸�Ĳ���¼�
*	szDevName		[OUT]���ط����¼����豸����
*	pulDevNameLen	[IN,OUT]����/���������������ʱ��ʾ���������ȣ����ʱ��ʾ�豸���Ƶ���Ч����,���Ȱ����ַ���������
*	pulEvent		[OUT]�¼����͡�1��ʾ���룬2��ʾ�γ�
*	��ע: �ú������������õ�
*/
ULONG DEVAPI SKF_WaitForDevEvent(LPSTR szDevName,ULONG *pulDevNameLen, ULONG *pulEvent);
ULONG DEVAPI SKF_CancelWaitForDevEvent();

/*
*	��õ�ǰϵͳ�е��豸�б�
*	bPresent		[IN]ΪTRUE��ʾȡ��ǰ�豸״̬Ϊ���ڵ��豸�б���ΪFALSE��ʾȡ��ǰ����֧�ֵ��豸�б�
*	szNameList		[OUT]�豸�����б�������ò���ΪNULL������pulSize��������Ҫ���ڴ�ռ��С��ÿ���豸�������Ե���'\0'��������˫'\0'��ʾ�б��Ľ���
*	pulSize			[IN,OUT]��������������豸�����б��Ļ��������ȣ��������������szNameList����Ҫ�Ŀռ��С
*/
ULONG DEVAPI SKF_EnumDev(BOOL bPresent, LPSTR szNameList, ULONG *pulSize);
/*
*	ͨ���豸���������豸�������豸�ľ��
*	szName		[IN]�豸����
*	phDev		[OUT]�����豸�������
*/
ULONG DEVAPI SKF_ConnectDev (LPSTR szName, DEVHANDLE *phDev);
/*
*	�Ͽ�һ���Ѿ����ӵ��豸�����ͷž����
*	hDev		[IN]�����豸ʱ���ص��豸���
*/
ULONG DEVAPI SKF_DisConnectDev (DEVHANDLE hDev);
/*
*	��ȡ�豸�Ƿ���ڵ�״̬
*	szDevName	[IN]��������
*	pulDevState	[OUT]�����豸״̬
*/
ULONG DEVAPI SKF_GetDevState(LPSTR szDevName, ULONG *pulDevState);
/*
*	�����豸��ǩ
*	hDev		[IN]�����豸ʱ���ص��豸���
*	szLabel		[OUT]�豸��ǩ�ַ��������ַ���ӦС��32�ֽ�
*/
ULONG DEVAPI SKF_SetLabel(DEVHANDLE hDev, LPSTR szLabel);
/*
*	��ȡ�豸��һЩ������Ϣ�������豸��ǩ��������Ϣ��֧�ֵ��㷨��
*	hDev		[IN]�����豸ʱ���ص��豸���
*	pDevInfo	[OUT]�����豸��Ϣ
*/
ULONG DEVAPI SKF_GetDevInfo (DEVHANDLE hDev, DEVINFO *pDevInfo);
/*
*	����豸�Ķ�ռʹ��Ȩ
*	hDev		[IN]�����豸ʱ���ص��豸���
*	ulTimeOut	[IN]��ʱʱ�䣬��λΪ���롣���Ϊ0xFFFFFFFF��ʾ���޵ȴ�
*/	
ULONG DEVAPI SKF_LockDev (DEVHANDLE hDev, ULONG ulTimeOut);
/*
*	�ͷŶ��豸�Ķ�ռʹ��Ȩ
*	hDev		[IN]�����豸ʱ���ص��豸���
*/
ULONG DEVAPI SKF_UnlockDev (DEVHANDLE hDev);

/*
*	������ֱ�ӷ��͸��豸�������ؽ��
*	hDev			[IN]�豸���
*	pbCommand		[IN]�豸����
*	ulCommandLen	[IN]�����
*	pbData			[OUT]���ؽ������
*	pulDataLen		[IN,OUT]���뻺�������ȣ�����������ݳ���
*/
ULONG DEVAPI SKF_Transmit(DEVHANDLE hDev, BYTE* pbCommand, ULONG ulCommandLen, BYTE* pbData, ULONG* pulDataLen);


/************************************************************************/
/*  2. ���ʿ���	ϵ�к���                                           */
/*	SKF_ChangeDevAuthKey												*/
/*	SKF_DevAuth															*/
/*	SKF_ChangePIN														*/
/*	SKF_GetPINInfo														*/
/*	SKF_VerifyPIN														*/
/*	SKF_UnblockPIN														*/
/*	SKF_ClearSecureState												*/
/************************************************************************/

/*
*	�����豸��֤��Կ
*	hDev		[IN]����ʱ���ص��豸���
*	pbKeyValue	[IN]��Կֵ
*	ulKeyLen	[IN]��Կ����
*/
ULONG DEVAPI SKF_ChangeDevAuthKey (DEVHANDLE hDev, BYTE *pbKeyValue, ULONG ulKeyLen);

/*
*	�豸��֤���豸��Ӧ�ó������֤
*	hDev			[IN]����ʱ���ص��豸���
*	pbAuthData		[IN]��֤����
*	ulLen			[IN]��֤���ݵĳ���
*/
ULONG DEVAPI SKF_DevAuth (DEVHANDLE hDev, BYTE *pbAuthData,ULONG ulLen);
/*
*	�޸�PIN�������޸�Admin��User��PIN�����ԭPIN���󣬷���ʣ�����Դ�������ʣ�����Ϊ0ʱ����ʾPIN�Ѿ�������
*	hApplication	[IN]Ӧ�þ��
*	ulPINType		[IN]PIN���ͣ�����ΪADMIN_TYPE=0����USER_TYPE=1
*	szOldPIN		[IN]ԭPINֵ
*	szNewPIN		[IN]��PINֵ
*	pulRetryCount	[OUT]���������Դ���
*/
ULONG DEVAPI SKF_ChangePIN (HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *pulRetryCount);

/*
*	��ȡPIN����Ϣ������������Դ�������ǰʣ�����Դ������Լ���ǰPIN���Ƿ�Ϊ����Ĭ��PIN��
*	hApplication		[IN]Ӧ�þ��
*	ulPINType			[IN]PIN����
*	pulMaxRetryCount	[OUT]������Դ���
*	pulRemainRetryCount	[OUT]��ǰʣ�����Դ�������Ϊ0ʱ��ʾ������
*	pbDefaultPin		[OUT]�Ƿ�Ϊ����Ĭ��PIN��
*/
ULONG DEVAPI SKF_GetPINInfo(HAPPLICATION hApplication, ULONG  ulPINType, ULONG *pulMaxRetryCount, ULONG *pulRemainRetryCount, BOOL *pbDefaultPin);

/*
*	У��PIN�롣У��ɹ��󣬻�����Ӧ��Ȩ�ޣ����PIN����󣬻᷵��PIN������Դ����������Դ���Ϊ0ʱ��ʾPIN���Ѿ�����
*	hApplication	[IN]Ӧ�þ��
*	ulPINType		[IN]PIN���ͣ�����ΪADMIN_TYPE=0����USER_TYPE=1
*	szPIN			[IN]PINֵ
*	pulRetryCount	[OUT]�����󷵻ص����Դ���
*/
ULONG DEVAPI SKF_VerifyPIN (HAPPLICATION hApplication, ULONG  ulPINType, LPSTR szPIN, ULONG *pulRetryCount);
/*
*	���û���PIN��������ͨ�����øú����������û�PIN�롣
*	�������û�PIN�뱻���ó���ֵ���û�PIN������Դ���Ҳ�ָ���ԭֵ��
*	hApplication	[IN]Ӧ�þ��
*	szAdminPIN		[IN]����ԱPIN��
*	szNewUserPIN	[IN]�µ��û�PIN��
*	pulRetryCount	[OUT]����ԱPIN�����ʱ������ʣ�����Դ���
*/
ULONG DEVAPI SKF_UnblockPIN (HAPPLICATION hApplication, LPSTR szAdminPIN, LPSTR szNewUserPIN,  ULONG *pulRetryCount);


ULONG DEVAPI SKF_GenRemoteUnblockRequest(HAPPLICATION hApplication, BYTE *pbRandom,ULONG ulRandomLen);

/*
*	���û���PIN��������ͨ�����øú����������û�PIN�롣
*	�������û�PIN�뱻���ó���ֵ���û�PIN������Դ���Ҳ�ָ���ԭֵ��
*	hApplication	[IN]Ӧ�þ��
*	pbCipherPIN		[IN]����ԱPIN��sha1��ȡ16λ��ΪKEY����KEY�����µ��û�PIN�õ����ģ����������KEY��MAC���ӵ����ĵĺ���
*	pulRetryCount	[OUT]����ԱPIN�����ʱ������ʣ�����Դ���
*/
ULONG DEVAPI SKF_RemoteUnblockPIN (HAPPLICATION hApplication, BYTE *pbCipherPIN, ULONG ulCipherPINLen,  ULONG *pulRetryCount);

/*
*	���Ӧ�õ�ǰ�İ�ȫ״̬
*	hApplication	[IN]Ӧ�þ��
*/
ULONG DEVAPI SKF_ClearSecureState (HAPPLICATION hApplication);

/************************************************************************/
/*  3. Ӧ�ù���ϵ�к���                                           */
/*	SKF_CreateApplication												*/
/*	SKF_EnumApplication													*/
/*	SKF_DeleteApplication												*/
/*	SKF_OpenApplication													*/
/*	SKF_CloseApplication												*/
/************************************************************************/

/*
*	����һ��Ӧ��
*	hDev					[IN]�����豸ʱ���ص��豸���
*	szAppName				[IN]Ӧ������
*	szAdminPIN				[IN]����ԱPIN
*	dwAdminPinRetryCount	[IN]����ԱPIN������Դ���
*	szUserPIN				[IN]�û�PIN
*	dwAdminPinRetryCount	[IN]�û�PIN������Դ���
*	dwCreateFileRights		[IN]�ڸ�Ӧ���´����ļ���������Ȩ��
*	phApplication			[OUT]Ӧ�õľ��
*/
ULONG DEVAPI SKF_CreateApplication(DEVHANDLE hDev, LPSTR szAppName, LPSTR szAdminPin, DWORD dwAdminPinRetryCount,LPSTR szUserPin, DWORD dwUserPinRetryCount,DWORD dwCreateFileRights, HAPPLICATION *phApplication);

/*
*	ö���豸�������ڵ�����Ӧ��
*	hDev			[IN]�����豸ʱ���ص��豸���
*	szAppName		[OUT]����Ӧ�������б�, ����ò���Ϊ�գ�����pulSize��������Ҫ���ڴ�ռ��С��
*						 ÿ��Ӧ�õ������Ե���'\0'��������˫'\0'��ʾ�б��Ľ�����
*	pulSize			[IN,OUT]�������������Ӧ�����ƵĻ��������ȣ��������������szAppName��ռ�õĵĿռ��С
*/
ULONG DEVAPI SKF_EnumApplication(DEVHANDLE hDev, LPSTR szAppName,ULONG *pulSize);
/*
*	ɾ��ָ����Ӧ��
*	hDev			[IN]�����豸ʱ���ص��豸���
*	szAppName		[IN]Ӧ������
*/
ULONG DEVAPI SKF_DeleteApplication(DEVHANDLE hDev, LPSTR szAppName);
/*
*	��ָ����Ӧ��
*	hDev			[IN]�����豸ʱ���ص��豸���
*	szAppName		[IN]Ӧ������
*	phApplication	[OUT]Ӧ�õľ��
*/
ULONG DEVAPI SKF_OpenApplication(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *phApplication);
/*
*	�ر�Ӧ�ò��ͷ�Ӧ�þ��
*	hApplication	[IN]Ӧ�õľ��
*/
ULONG DEVAPI SKF_CloseApplication(HAPPLICATION hApplication);

/************************************************************************/
/*  4. �ļ�����				                                            */
/*	SKF_CreateFile														*/
/*	SKF_DeleteFile														*/
/*	SKF_EnumFiles														*/
/*	SKF_GetFileInfo														*/
/*	SKF_ReadFile														*/
/*	SKF_WriteFile														*/
/************************************************************************/

/*
*	����һ���ļ��������ļ�ʱҪָ���ļ������ƣ���С���Լ��ļ��Ķ�дȨ��
*	hApplication		[IN]Ӧ�þ��
*	szFileName			[IN]�ļ����ƣ����Ȳ��ô���32���ֽ�
*	ulFileSize			[IN]�ļ���С
*	ulReadRights		[IN]�ļ���Ȩ��
*	ulWriteRights		[IN]�ļ�дȨ��
*/
ULONG DEVAPI SKF_CreateFile (HAPPLICATION hApplication, LPSTR szFileName, ULONG ulFileSize, ULONG ulReadRights,ULONG ulWriteRights);

/*
*	ɾ��ָ���ļ����ļ�ɾ�����ļ���д���������Ϣ����ʧ���ļ����豸�е�ռ�õĿռ佫���ͷš�
*	hApplication		[IN]Ҫɾ���ļ����ڵ�Ӧ�þ��
*	szFileName			[IN]Ҫɾ���ļ�������
*/
ULONG DEVAPI SKF_DeleteFile (HAPPLICATION hApplication, LPSTR szFileName);
/*
*	ö��һ��Ӧ���´��ڵ������ļ�
*	hApplication		[IN]Ӧ�õľ��
*	szFileList			[OUT]�����ļ������б����ò���Ϊ�գ���pulSize�����ļ���Ϣ����Ҫ�Ŀռ��С��ÿ���ļ������Ե���'\0'��������˫'\0'��ʾ�б��Ľ�����
*	pulSize				[OUT]����Ϊ���ݻ������Ĵ�С�����Ϊʵ���ļ����ƵĴ�С
*/
ULONG DEVAPI SKF_EnumFiles (HAPPLICATION hApplication, LPSTR szFileList, ULONG *pulSize);

/*
*	��ȡӦ���ļ���������Ϣ�������ļ��Ĵ�С��Ȩ�޵�
*	hApplication		[IN]�ļ�����Ӧ�õľ��
*	szFileName			[IN]�ļ�����
*	pFileInfo			[OUT]�ļ���Ϣ��ָ���ļ����Խṹ��ָ��
*/
ULONG DEVAPI SKF_GetFileInfo (HAPPLICATION hApplication, LPSTR szFileName, FILEATTRIBUTE *pFileInfo);

/*
*	��ȡ�ļ�����
*	hApplication		[IN]�ļ����ڵ�Ӧ�þ��
*	szFileName			[IN]�ļ���
*	ulOffset			[IN]�ļ���ȡƫ��λ��
*	ulSize				[IN]Ҫ��ȡ�ĳ���
*	pbOutData			[OUT]�������ݵĻ�����
*	pulOutLen			[OUT]�����ʾ�����Ļ�������С�������ʾʵ�ʶ�ȡ���ص����ݴ�С
*/
ULONG DEVAPI SKF_ReadFile (HAPPLICATION hApplication, LPSTR szFileName, ULONG ulOffset, ULONG ulSize, BYTE * pbOutData, ULONG *pulOutLen);

/*
*	д���ݵ��ļ���
*	hApplication		[IN]�ļ����ڵ�Ӧ�þ��
*	szFileName			[IN]�ļ���
*	ulOffset			[IN]д���ļ���ƫ����
*	pbData				[IN]д�����ݻ�����
*	ulSize				[IN]д�����ݵĴ�С
*/
ULONG DEVAPI SKF_WriteFile (HAPPLICATION hApplication, LPSTR szFileName, ULONG  ulOffset, BYTE *pbData, ULONG ulSize);


/************************************************************************/
/*  5. ��������	ϵ�к���                                           */
/*	SKF_CreateContainer													*/
/*	SKF_DeleteContainer													*/
/*	SKF_EnumContainer													*/
/*	SKF_OpenContainer													*/
/*	SKF_CloseContainer													*/
/*	SKF_GetContainerType												*/
/*	SKF_ImportCertificate												*/
/*	SKF_ExportCertificate												*/
/************************************************************************/

/*
*	��Ӧ���½���ָ�����Ƶ������������������
*	hApplication		[IN]Ӧ�þ��
*	szContainerName		[IN]ASCII�ַ�������ʾ���������������ƣ��������Ƶ���󳤶Ȳ��ܳ���64�ֽ�
*	phContainer			[OUT]�����������������������
*/
ULONG DEVAPI SKF_CreateContainer (HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer);
/*
*	��Ӧ����ɾ��ָ�����Ƶ��������ͷ�������ص���Դ
*	hApplication		[IN]Ӧ�þ��
*	szContainerName		[IN]ָ��ɾ������������
*/
ULONG DEVAPI SKF_DeleteContainer(HAPPLICATION hApplication, LPSTR szContainerName);
/*
*	ö��Ӧ���µ������������������������б�
*	hApplication		[IN]Ӧ�þ��
*	szContainerName		[OUT]ָ�����������б�������������˲���ΪNULLʱ��pulSize��ʾ������������Ҫ�������ĳ��ȣ�����˲�����ΪNULLʱ���������������б���ÿ���������Ե���'\0'Ϊ�������б���˫'\0'����
*	pulSize				[OUT]����ǰ��ʾszContainerName�������ĳ��ȣ��������������б��ĳ���
*/
ULONG DEVAPI SKF_EnumContainer(HAPPLICATION	hApplication, LPSTR  szContainerName, ULONG* pulSize);
/*
*	��ȡ�������
*	hApplication		[IN]Ӧ�þ��
*	szContainerName		[IN]��������
*	phContainer			[OUT]�������������ľ��
*/
ULONG DEVAPI SKF_OpenContainer(HAPPLICATION hApplication,LPSTR szContainerName,HCONTAINER *phContainer);

/*
*	�ر�������������ͷ�������������Դ
*	hContainer			[OUT]�������
*/
ULONG DEVAPI SKF_CloseContainer(HCONTAINER hContainer);

/*
��ȡ����������
hContainer	[IN] ���������
pulContainerType	[OUT] ��õ��������͡�ָ��ָ���ֵΪ0��ʾδ������δ�������ͻ���Ϊ��������Ϊ1��ʾΪRSA������Ϊ2��ʾΪECC������
*/
ULONG DEVAPI SKF_GetContainerType(HCONTAINER hContainer, ULONG *pulContainerType);

/*
�������ڵ�������֤��
hContainer	[IN] ���������
bSignFlag	[IN] TRUE��ʾǩ��֤�飬FALSE��ʾ����֤��
pbCert		[IN] ֤�黺����
ulCertLen	[IN] ����������
*/
ULONG DEVAPI SKF_ImportCertificate(HCONTAINER hContainer, BOOL bSignFlag,  BYTE* pbCert, ULONG ulCertLen);

/*
���������ڵ�����֤��
hContainer	[IN] ���������
bSignFlag	[IN] TRUE��ʾǩ��֤�飬FALSE��ʾ����֤��
pbCert		[OUT] ֤�黺����
ulCertLen	[IN,OUT] ���뻺�������ȣ����֤�����ݳ���
*/
ULONG DEVAPI SKF_ExportCertificate(HCONTAINER hContainer, BOOL bSignFlag,  BYTE* pbCert, ULONG *pulCertLen);

/************************************************************************/
/*  6. �������	ϵ�к���                                           */
/*	SKF_GetRandom														*/
/*	SKF_GenRSAKeyPair													*/
/*	SKF_ImportRSAKeyPair												*/
/*	SKF_RSASignData														*/
/*	SKF_RSAVerify														*/
/*	SKF_RSAExportSessionKey												*/
/*	SKF_GenECCKeyPair													*/
/*	SKF_ImportECCKeyPair												*/
/*	SKF_ECCSignData														*/
/*	SKF_ECCVerify														*/
/*	SKF_GenerateAgreementDataWithECC									*/
/*	SKF_GenerateAgreementDataAndKeyWithECC								*/
/*	SKF_GenerateKeyWithECC												*/
/*	SKF_ECCExportSessionKey												*/
/*	SKF_ExportPublicKey													*/
/*	SKF_ImportSessionKey												*/
/*	SKF_EncryptInit														*/
/*	SKF_Encrypt															*/
/*	SKF_EncryptUpdate													*/
/*	SKF_EncryptFinal													*/
/*	SKF_DecryptInit														*/
/*	SKF_Decrypt															*/
/*	SKF_DecryptUpdate													*/
/*	SKF_DecryptFinal													*/
/*	SKF_DigestInit														*/
/*	SKF_Digest															*/
/*	SKF_DigestUpdate													*/
/*	SKF_DegistFinal														*/
/*	SKF_MACInit															*/
/*	SKF_MAC																*/
/*	SKF_MACUpdate														*/
/*	SKF_MACFinal														*/
/*	SKF_CloseHandle														*/
/************************************************************************/

/*
*	����ָ�����ȵ������
*	hDev			[IN] �豸���
*	pbRandom		[OUT] ���ص������
*	ulRandomLen		[IN] ���������
*/
ULONG DEVAPI SKF_GenRandom (DEVHANDLE hDev, BYTE *pbRandom,ULONG ulRandomLen);

/*
*	���豸����RSA��Կ�Բ��������
*	hDev			[IN] �豸���
*	ulBitsLen		[IN] ��Կģ��
*	pBlob			[OUT] ���صĹ�Կ���ݽṹ
*/
ULONG DEVAPI SKF_GenRSAKeyPair (HCONTAINER hContainer, ULONG ulBitsLen, RSAPUBLICKEYBLOB *pBlob);



/*
*	����RSA���ܹ�˽Կ��
*	hContainer		[IN] �������
*	ulSymAlgId		[IN] �Գ��㷨��Կ��ʶ
*	pbWrappedKey	[IN] ʹ�ø�������ǩ����Կ�����ĶԳ��㷨��Կ
*	ulWrappedKeyLen	[IN] �����ĶԳ��㷨��Կ����
*	pbEncryptedData	[IN] �Գ��㷨��Կ������RSA����˽Կ��˽Կ�ĸ�ʽ��ѭPKCS #1 v2.1: RSA Cryptography Standard�е�˽Կ��ʽ����
*	ulEncryptedDataLen	[IN] �Գ��㷨��Կ������RSA���ܹ�˽Կ�Գ���
*/
ULONG DEVAPI SKF_ImportRSAKeyPair ( HCONTAINER hContainer, ULONG ulSymAlgId, 
								   BYTE *pbWrappedKey, ULONG ulWrappedKeyLen,
								   BYTE *pbEncryptedData, ULONG ulEncryptedDataLen);

/*
*	ʹ��hContainerָ��������ǩ��˽Կ����ָ������pbData��������ǩ����ǩ����Ľ����ŵ�pbSignature������������pulSignLenΪǩ���ĳ���
*	hContainer		[IN] ����ǩ����˽Կ�����������
*	pbData			[IN] ��ǩ��������
*	ulDataLen		[IN] ǩ�����ݳ��ȣ�Ӧ������RSA��Կģ��-11
*	pbSignature		[OUT] ���ǩ������Ļ�����ָ�룬���ֵΪNULL������ȡ��ǩ���������
*	pulSigLen		[IN,OUT] ����Ϊǩ�������������С�����Ϊǩ���������
*/
ULONG DEVAPI SKF_RSASignData(HCONTAINER hContainer, BYTE *pbData, ULONG  ulDataLen, BYTE *pbSignature, ULONG *pulSignLen);
/*
*	��֤RSAǩ������pRSAPubKeyBlob�ڵĹ�Կֵ�Դ���ǩ���ݽ�����ǩ��
*	hDev			[IN] �����豸ʱ���ص��豸���
*	pRSAPubKeyBlob	[IN] RSA��Կ���ݽṹ
*	pbData			[IN] ����֤ǩ��������
*	ulDataLen		[IN] ���ݳ��ȣ�Ӧ�����ڹ�Կģ��-11
*	pbSignature		[IN] ����֤��ǩ��ֵ
*	ulSigLen		[IN] ǩ��ֵ���ȣ�����Ϊ��Կģ��
*/
ULONG DEVAPI SKF_RSAVerify (DEVHANDLE hDev , RSAPUBLICKEYBLOB* pRSAPubKeyBlob, BYTE *pbData, ULONG  ulDataLen, 
							BYTE *pbSignature, ULONG ulSignLen);
/*
*	���ɻỰ��Կ�����ⲿ��Կ���������
*	hContainer		[IN] �������
*	ulAlgID			[IN] �Ự��Կ���㷨��ʶ
*	pPubKey			[IN] ���ܻỰ��Կ��RSA��Կ���ݽṹ
*	pbData			[OUT] �����ļ��ܻỰ��Կ���ģ�����PKCS#1v1.5��Ҫ���װ
*	pulDataLen		[OUT] ���ص������ݳ���
*	phSessionKey	[OUT] ��������Կ���
*/

ULONG DEVAPI SKF_RSAExportSessionKey (HCONTAINER hContainer, ULONG ulAlgId, RSAPUBLICKEYBLOB *pPubKey, BYTE *pbData, ULONG  *pulDataLen, HANDLE *phSessionKey);


/*
*	ֱ��ʹ���ⲿ�����RSA��Կ������������PKCS1�������㲢������
*	hDev			[IN] �豸���
*	pRSAPubKeyBlob	[IN] RSA��Կ���ݽṹ
*	pbInput			[IN] ָ��������ԭʼ���ݻ�����
*	ulInputLen		[IN] ������ԭʼ���ݵĳ��ȣ�����Ϊ��Կģ��
*	pbOutput		[OUT] ָ��RSA��Կ������������������ò���ΪNULL������pulOutputLen������������ʵ�ʳ���
*	pulOutputLen	[in, OUT] ����ǰ��ʾpbOutput�������ĳ��ȣ�����RSA��Կ��������ʵ�ʳ���
*/
ULONG DEVAPI SKF_ExtRSAEncrypt(DEVHANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob,BYTE* pbInput, ULONG ulInputLen, 
							   BYTE* pbOutput, ULONG* pulOutputLen);


/*
*	����ECCǩ����Կ�Բ����ǩ����Կ��
*	hContainer		[IN] �������
*	ֻ֧��SGD_SM2_1�㷨
*	pBlob			[OUT] ����ECC��Կ���ݽṹ
*/
ULONG DEVAPI SKF_GenECCKeyPair (HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pBlob);

/*
*	����ECC��˽Կ��
*	hContainer		[IN] �������
*	pbWrapedData	[IN] ���ܱ�����ECC���ܹ�˽Կ������
*	ulWrapedLen		[IN] ���ݳ���
*/

ULONG DEVAPI SKF_ImportECCKeyPair (  HCONTAINER hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob);

/*
*	ECC����ǩ��������ECC�㷨��ָ��˽ԿhKey����ָ������pbData��������ǩ����ǩ����Ľ����ŵ�pbSignature������������pulSignLenΪǩ��ֵ�ĳ���
*	hContainer		[IN] ����ǩ����˽Կ�����������
*	pbData			[IN] ��ǩ��������
*	ulDataLen		[IN] ��ǩ�����ݳ��ȣ�����С����Կģ��
*	pbSignature		[OUT] ǩ��ֵ��ΪNULLʱ���ڻ��ǩ��ֵ�ĳ���
*	pulSigLen		[IN,OUT] ����ǩ��ֵ���ȵ�ָ�� 
*/

ULONG DEVAPI SKF_ECCSignData (HCONTAINER hContainer, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature);

/*
*	��ECC��Կ�����ݽ�����ǩ
*	hDev			[IN] �豸���
*	pECCPubKeyBlob	[IN] ECC��Կ���ݽṹ
*	pbData			[IN] ����֤ǩ��������
*	ulDataLen		[IN] ���ݳ���
*	pbSignature		[IN] ����֤��ǩ��ֵ
*	ulSigLen		[IN] ǩ��ֵ����
*/
ULONG DEVAPI SKF_ECCVerify (DEVHANDLE hDev , ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature);

/*
*	���ɻỰ��Կ�����ⲿ��Կ���������
*	hContainer		[IN] �������
*	ulAlgID			[IN] �Ự��Կ���㷨��ʶ
*	pPubKey			[IN] ����������Կ����Կ�ṹ
*	pbData			[OUT] �����ļ��ܻỰ��Կ����, ע��˴�����ĳ���Ҫ����ECCCIPHERBLOB�ṹ�ĳ��ȣ��ṹ�ں�ָ��
*	phSessionKey	[OUT] �Ự��Կ���
*/
ULONG DEVAPI SKF_ECCExportSessionKey (HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pPubKey, PECCCIPHERBLOB pData, HANDLE *phSessionKey);


/*
*	ʹ��ECC��ԿЭ���㷨��Ϊ����Ự��Կ������Э�̲�����������ʱECC��Կ�ԵĹ�Կ��Э�̾��
*	hContainer		[IN] �������
*	ulAlgId			[IN] �Ự��Կ�㷨��ʶ
*	pTempECCPubKeyBlob	[OUT] ������ʱECC��Կ
*	pbID			[IN] ���𷽵�ID
*	ulIDLen			[IN] ����ID�ĳ��ȣ�������32
*	phAgreementHandle	[OUT] ���ص���ԿЭ�̾��
*/
ULONG DEVAPI SKF_GenerateAgreementDataWithECC (HCONTAINER hContainer, ULONG ulAlgId,ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,BYTE* pbID, ULONG ulIDLen,HANDLE *phAgreementHandle);

/*
*	ʹ��ECC��ԿЭ���㷨������Э�̲���������Ự��Կ�������ʱECC��Կ�Թ�Կ�������ز�������Կ���
*	hContainer					[IN] �������
*	ulAlgId						[IN] �Ự��Կ�㷨��ʶ
*	pSponsorECCPubKeyBlob		[IN] ���𷽵�ECC��Կ
*	pSponsorTempECCPubKeyBlob	[IN] ���𷽵���ʱECC��Կ
*	pTempECCPubKeyBlob			[OUT] ��Ӧ������ʱECC��Կ
*	pbID						[IN] ��Ӧ����ID
*	ulIDLen						[IN] ��Ӧ��ID�ĳ��ȣ�������32
*	pbSponsorID					[IN] ���𷽵�ID
*	ulSponsorIDLen				[IN] ����ID�ĳ��ȣ�������32
*	phKeyHandle					[OUT] ���صĶԳ��㷨��Կ���
*/
ULONG DEVAPI SKF_GenerateAgreementDataAndKeyWithECC(
	HANDLE hContainer, ULONG ulAlgId,
	ECCPUBLICKEYBLOB*  pSponsorECCPubKeyBlob,
	ECCPUBLICKEYBLOB*  pSponsorTempECCPubKeyBlob,
	ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
	BYTE* pbID, ULONG ulIDLen, BYTE *pbSponsorID, ULONG ulSponsorIDLen,
	HANDLE *phKeyHandle);

/*
*	ʹ��ECC��ԿЭ���㷨��ʹ������Э�̾������Ӧ����Э�̲�������Ự��Կ��ͬʱ���ػỰ��Կ���
*	hAgreementHandle			[IN] ��ԿЭ�̾��
*	pECCPubKeyBlob				[IN] �ⲿ�������Ӧ��ECC��Կ
*	pTempECCPubKeyBlob			[IN] �ⲿ�������Ӧ����ʱECC��Կ
*	pbID						[IN] ��Ӧ����ID
*	ulIDLen						[IN] ��Ӧ��ID�ĳ��ȣ�������32
*	phKeyHandle					[OUT] ���ص���Կ���
*/
ULONG DEVAPI SKF_GenerateKeyWithECC (HANDLE hAgreementHandle,
									 ECCPUBLICKEYBLOB*  pECCPubKeyBlob,
									 ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
									 BYTE* pbID, ULONG ulIDLen, HANDLE *phKeyHandle);


/*
*	���������е�ǩ����Կ���߼��ܹ�Կ
*	hContainer		[IN] �������
*	bSignFlag		[IN] TRUE��ʾ����ǩ����Կ��FALSE��ʾ�������ܹ�Կ
*	pbBlob			[OUT] ָ��RSA��Կ�ṹ��RSAPUBLICKEYBLOB������ECC��Կ�ṹ��ECCPUBLICKEYBLOB��������˲���ΪNULLʱ����pulBlobLen����pbBlob�ĳ���
*	pulBlobLen		[IN,OUT] ����ʱ��ʾpbBlob�ĳ��ȣ����ص�����Կ�ṹ�Ĵ�С
*/
ULONG DEVAPI SKF_ExportPublicKey (HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbBlob, ULONG* pulBlobLen);

/*
*	����Ự��Կ
*	hDev			[IN] �豸���
*	pECCPubKeyBlob	[IN] ����ʹ�õĹ�Կ
*	pbPlainText		[IN] Ҫ���ܵ�����
*	ulPlainTextLen	[IN] ���ݳ���
*	pCipherText		[OUT] ���ص�����
*/
ULONG DEVAPI SKF_ExtECCEncrypt(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob,
							   BYTE* pbPlainText, ULONG ulPlainTextLen, 
							   PECCCIPHERBLOB pCipherText);


/*
*	����Ự��Կ
*	hContainer		[IN] �������
*	ulAlgID			[IN] �Ự��Կ���㷨��ʶ
*	pbWrapedData	[IN] Ҫ���������
*	ulWrapedLen		[IN] ���ݳ���
*	phKey			[OUT] ���ػỰ��Կ���
*/
ULONG DEVAPI SKF_ImportSessionKey (HCONTAINER hContainer, ULONG ulAlgId,BYTE *pbWrapedData,ULONG ulWrapedLen,HANDLE *phKey);


/*
*	���ݼ��ܳ�ʼ�����������ݼ��ܵ��㷨��ز�����
*	hKey			[IN] ������Կ���
*	EncryptParam	[IN] ���������㷨��ز������㷨��ʶ�š���Կ���ȡ���ʼ��������ʼ�������ȡ���䷽��������ģʽ������ֵ��λ����
*/
ULONG DEVAPI SKF_EncryptInit (HANDLE hKey, BLOCKCIPHERPARAM EncryptParam);

/*
*	��һ�������ݵļ��ܲ�����
��ָ��������Կ��ָ�����ݽ��м��ܣ������ܵ�����ֻ����һ�����飬���ܺ�����ı��浽ָ���Ļ������С�
SKF_Encryptֻ�Ե����������ݽ��м��ܣ��ڵ���SKF_Encrypt֮ǰ���������SKF_EncryptInit��ʼ�����ܲ�����
SKF_Encypt�ȼ����ȵ���SKF_EncryptUpdate�ٵ���SKF_EncryptFinal��
*	hKey			[IN] ������Կ���
*	pbData			[IN] ����������
*	ulDataLen		[IN] ���������ݳ���
*	pbEncryptedData [OUT] ���ܺ�����ݻ�����ָ��
*	pulEncryptedLen [IN,OUT] ���룬�����Ļ�������С����������ؼ��ܺ������
����
*	�ɹ�: SAR_OK
*	ʧ��: SAR_FAIL SAR_MEMORYERR SAR_UNKNOWNERR  SAR_INVALIDPARAMERR SAR_BUFFER_TOO_SMALL   
*/
ULONG DEVAPI SKF_Encrypt(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);


/*
*	����������ݵļ��ܲ�����
��ָ��������Կ��ָ�����ݽ��м��ܣ������ܵ����ݰ���������飬���ܺ�����ı��浽ָ���Ļ������С�
SKF_EncryptUpdate�Զ���������ݽ��м��ܣ��ڵ���SKF_EncryptUpdate֮ǰ���������SKF_EncryptInit��ʼ�����ܲ�����
�ڵ���SKF_EncryptUpdate֮�󣬱������SKF_EncryptFinal�������ܲ�����
*	hKey			[IN] ������Կ���
*	pbData			[IN] ����������
*	ulDataLen		[IN] ���������ݳ���
*	pbEncryptedData [OUT] ���ܺ�����ݻ�����ָ��
*	pulEncryptedLen [OUT] ���ؼ��ܺ�����ݳ���
*/
ULONG DEVAPI SKF_EncryptUpdate(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);

/*
*	��������������ݵļ��ܣ�����ʣ����ܽ����
�ȵ���SKF_EncryptInit��ʼ�����ܲ�����
�ٵ���SKF_EncryptUpdate�Զ���������ݽ��м��ܣ�
������SKF_EncryptFinal��������������ݵļ��ܡ�
*	hKey			[IN] ������Կ���
*	pbEncryptedData [OUT] ���ܽ���Ļ�����
*	pulEncryptedLen [OUT] ���ܽ���ĳ���
*/
ULONG DEVAPI SKF_EncryptFinal (HANDLE hKey, BYTE *pbEncryptedData, ULONG *ulEncryptedDataLen );

/*
*	���ݽ��ܳ�ʼ�������ý�����Կ��ز�����
����SKF_DecryptInit֮�󣬿��Ե���SKF_Decrypt�Ե����������ݽ��н��ܣ�
Ҳ���Զ�ε���SKF_DecryptUpdate֮���ٵ���SKF_DecryptFinal��ɶԶ���������ݵĽ��ܡ�
*	hKey [IN] ������Կ���
*	DecryptParam [IN] ���������㷨��ز������㷨��ʶ�š���Կ���ȡ���ʼ��������ʼ�������ȡ���䷽��������ģʽ������ֵ��λ����
*/
ULONG DEVAPI SKF_DecryptInit (HANDLE hKey, BLOCKCIPHERPARAM DecryptParam);

/*
*	�����������ݵĽ��ܲ���
��ָ��������Կ��ָ�����ݽ��н��ܣ������ܵ�����ֻ����һ�����飬���ܺ�����ı��浽ָ���Ļ�������
SKF_Decryptֻ�Ե����������ݽ��н��ܣ��ڵ���SKF_Decrypt֮ǰ���������SKF_DecryptInit��ʼ��
���ܲ���
SKF_Decypt�ȼ����ȵ���SKF_DecryptUpdate�ٵ���SKF_DecryptFinal
*	hKey			[IN] ������Կ���
*	pbEncryptedData [IN] ����������
*	ulEncryptedLen	[IN] ���������ݳ���
*	pbData			[OUT] ָ����ܺ�����ݻ�����ָ�룬��ΪNULLʱ�ɻ�ý��ܺ�����ݳ���
*	pulDataLen		[IN��OUT] ���ؽ��ܺ�����ݳ���
*/
ULONG DEVAPI SKF_Decrypt(HANDLE hKey, BYTE * pbEncryptedData, ULONG ulEncryptedLen, BYTE * pbData, ULONG * pulDataLen);

/*
*	����������ݵĽ��ܲ�����
��ָ��������Կ��ָ�����ݽ��н��ܣ������ܵ����ݰ���������飬���ܺ�����ı��浽ָ���Ļ������С�
SKF_DecryptUpdate�Զ���������ݽ��н��ܣ��ڵ���SKF_DecryptUpdate֮ǰ���������SKF_DecryptInit��ʼ�����ܲ�����
�ڵ���SKF_DecryptUpdate֮�󣬱������SKF_DecryptFinal�������ܲ�����
*	hKey			[IN] ������Կ���
*	pbEncryptedData [IN] ����������
*	ulEncryptedLen	[IN] ���������ݳ���
*	pbData			[OUT] ָ����ܺ�����ݻ�����ָ��
*	pulDataLen		[IN��OUT] ���ؽ��ܺ�����ݳ���
*/
ULONG DEVAPI SKF_DecryptUpdate(HANDLE hKey, BYTE * pbEncryptedData, ULONG ulEncryptedLen, BYTE * pbData, ULONG * pulDataLen);

/*
*	��������������ݵĽ��ܡ�
*	hKey				[IN] ������Կ���
*	pbPlainText			[OUT] ָ����ܽ���Ļ�����������˲���ΪNULLʱ����pulPlainTextLen���ؽ��ܽ���ĳ���
*	pulDecyptedDataLen	[IN��OUT] ����ʱ��ʾpbPlainText�������ĳ��ȣ����ؽ��ܽ���ĳ��� 
*/
ULONG DEVAPI SKF_DecryptFinal (HANDLE hKey, BYTE *pbDecryptedData, ULONG *pulDecryptedDataLen);

/*
*	��ʼ����Ϣ�Ӵռ��������ָ��������Ϣ�Ӵյ��㷨��
*	hDev			[IN] �����豸ʱ���ص��豸���
*	ulAlgID			[IN] �Ӵ��㷨��ʶ
*	phHash			[OUT] �Ӵն�����
*/
ULONG DEVAPI SKF_DigestInit(DEVHANDLE hDev, ULONG ulAlgID,  ECCPUBLICKEYBLOB *pPubKey, unsigned char *pucID, ULONG ulIDLen, HANDLE *phHash);

/*
*	�Ե�һ�������Ϣ�����Ӵռ��㡣
*	hHash			[IN] �Ӵն�����
*	pbData			[IN] ָ����Ϣ���ݵĻ�����
*	ulDataLen		[IN] ��Ϣ���ݵĳ���
*	pbHashData		[OUT] �Ӵ����ݻ�����ָ�룬���˲���ΪNULLʱ����pulHashLen�����Ӵս���ĳ���
*	pulHashLen		[IN��OUT] ����ʱ��ʾpbHashData�������ĳ��ȣ������Ӵս���ĳ���
*/
ULONG DEVAPI SKF_Digest (HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen);
/*
*	�Զ���������Ϣ�����Ӵռ��㡣
*	hHash			[IN] �Ӵն�����
*	pbPart			[IN] ָ����Ϣ���ݵĻ�����
*	ulPartLen		[IN] ��Ϣ���ݵĳ���
*/
ULONG DEVAPI SKF_DigestUpdate (HANDLE hHash, BYTE *pbData, ULONG  ulDataLen);
/*
*	�������������Ϣ���Ӵռ�����������Ӵձ��浽ָ���Ļ�������
*	hHash			[IN] ��ϣ������
*	pHashData		[OUT] ���ص��Ӵ����ݻ�����ָ�룬����˲���NULLʱ����pulHashLen�����Ӵս���ĳ���
*	pulHashLen		[IN��OUT] ����ʱ��ʾ�Ӵս���ĳ��ȣ������Ӵ����ݵĳ���
*/
ULONG DEVAPI SKF_DigestFinal (HANDLE hHash, BYTE *pHashData, ULONG  *pulHashLen);

/*
*	��ʼ����Ϣ��֤�������������ü�����Ϣ��֤�����Կ��������������Ϣ��֤������
*	hKey			[IN] ������Ϣ��֤�����Կ���
*	MacParam		[IN] ��Ϣ��֤������ز�����������ʼ��������ʼ�������ȡ���䷽����
*	phMac			[OUT] ��Ϣ��֤�������
*/
ULONG DEVAPI SKF_MacInit (HANDLE hKey, BLOCKCIPHERPARAM* pMacParam, HANDLE *phMac);

/*
*	SKF_Mac���㵥һ�������ݵ���Ϣ��֤�롣
*	hMac			[IN] ��Ϣ��֤����
*	pbData			[IN] ָ����������ݵĻ�����
*	ulDataLen		[IN] ���������ݵĳ���
*	pbMacData		[OUT] ָ�������Mac���������˲���ΪNULLʱ����pulMacLen���ؼ����Mac����ĳ���
*	pulMacLen		[IN��OUT] ����ʱ��ʾpbMacData�������ĳ��ȣ����ؼ���Mac����ĳ���
*/
ULONG DEVAPI SKF_Mac(HANDLE hMac, BYTE* pbData, ULONG ulDataLen, BYTE *pbMacData, ULONG *pulMacLen);
/*
*	�������������ݵ���Ϣ��֤�롣
*	hMac			[IN] ��Ϣ��֤����
*	pbData			[IN] ָ����������ݵĻ�����
*	plDataLen		[IN] ���������ݵĳ���
*/
ULONG DEVAPI SKF_MacUpdate(HANDLE hMac, BYTE * pbData, ULONG ulDataLen);
/*
*	��������������ݵ���Ϣ��֤��������
*	hMac			[IN] ��Ϣ��֤����
*	pbMacData		[OUT] ָ����Ϣ��֤��Ļ����������˲���ΪNULLʱ����pulMacDataLen������Ϣ��֤�뷵�صĳ���
*	pulMacDataLen	[OUT] ����ʱ��ʾ��Ϣ��֤�뻺��������󳤶ȣ�������Ϣ��֤��ĳ���
*/
ULONG DEVAPI SKF_MacFinal (HANDLE hMac, BYTE *pbMacData, ULONG *pulMacDataLen);
/*
*	�رջỰ��Կ���Ӵա���Ϣ��֤������
*	hHandle			[IN] Ҫ�رյĶ�����
*/
ULONG DEVAPI SKF_CloseHandle(HANDLE hHandle);


/*****************************����Ϊ�����û�ʹ�����ṩ�Ĳ���API********************************************/

/*
*	�������ĶԳ���Կ��������Կ���
*	hDev			[IN] �豸���
*	pbKey			[IN] ָ��Ự��Կֵ�Ļ�����
*	ulAlgID			[IN] �Ự��Կ���㷨��ʶ
*	phKey			[OUT] ���ػỰ��Կ���
*/
ULONG DEVAPI SKF_SetSymmKey (DEVHANDLE hDev,  BYTE* pbKey, ULONG ulAlgID, HANDLE* phKey);

#ifdef __cplusplus
}
#endif


#endif //_SKFAPI_H_

