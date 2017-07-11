using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Security
{
    public class RSATool
    {
        private static readonly int DWKEYSIZE = 2048;

        /// <summary>
        /// RSA加密的密匙结构  公钥和私匙
        /// </summary>
        public struct RSAKey
        {
            public string PublicKey { get; set; }
            public string PrivateKey { get; set; }
        }

        #region 得到RSA的解谜的密匙对
        /// <summary>
        /// 得到RSA的解谜的密匙对
        /// </summary>
        /// <returns></returns>
        public static RSAKey GetRASKey()
        {
            //RSA密钥对的构造器  
            RsaKeyPairGenerator keyGenerator = new RsaKeyPairGenerator();

            //RSA密钥构造器的参数  
            RsaKeyGenerationParameters param = new RsaKeyGenerationParameters(
                Org.BouncyCastle.Math.BigInteger.ValueOf(3),
                new Org.BouncyCastle.Security.SecureRandom(),
                DWKEYSIZE,   //密钥长度  
                25);
            //用参数初始化密钥构造器  
            keyGenerator.Init(param);
            //产生密钥对  
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();
            //获取公钥和密钥  
            AsymmetricKeyParameter publicKey = keyPair.Public;
            AsymmetricKeyParameter privateKey = keyPair.Private;

            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);


            Asn1Object asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();

            byte[] publicInfoByte = asn1ObjectPublic.GetEncoded("UTF-8");
            Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
            byte[] privateInfoByte = asn1ObjectPrivate.GetEncoded("UTF-8");

            RSAKey item = new RSAKey()
            {
                PublicKey = Convert.ToBase64String(publicInfoByte),
                PrivateKey = Convert.ToBase64String(privateInfoByte)
            };
            return item;
        }
        #endregion
        private static AsymmetricKeyParameter GetPublicKeyParameter(string s)
        {
            s = s.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            byte[] publicInfoByte = Convert.FromBase64String(s);
            Asn1Object pubKeyObj = Asn1Object.FromByteArray(publicInfoByte);//这里也可以从流中读取，从本地导入   
            //pubKeyObj.GetDerEncoded();
            AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(publicInfoByte);
            return pubKey;
        }
        private static AsymmetricKeyParameter GetPrivateKeyParameter(string s)
        {
            s = s.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            byte[] privateInfoByte = Convert.FromBase64String(s);
            // Asn1Object priKeyObj = Asn1Object.FromByteArray(privateInfoByte);//这里也可以从流中读取，从本地导入   
            // PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            AsymmetricKeyParameter priKey = PrivateKeyFactory.CreateKey(privateInfoByte);
            return priKey;
        }
        #region 私钥解密
        /// <summary>
        /// 私钥解密
        /// </summary>
        /// <returns>明文</returns>
        public static byte[] Decrypt(string privateKeyStr, byte[] cipherData)
        {
            //解密  
            AsymmetricKeyParameter privateKey = GetPrivateKeyParameter(privateKeyStr);
            byte[] ResultData = Decrypt(privateKey, cipherData);
            return ResultData;
        }
        #endregion
        #region 私钥解密
        /// <summary>
        /// 私钥解密
        /// </summary>
        /// <returns>明文</returns>
        public static byte[] Decrypt(AsymmetricKeyParameter privateKey, byte[] cipherData)
        {
            //非对称加密算法，加解密用  
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());
            //解密  
            byte[] ResultData = null;
            try
            {
                engine.Init(false, privateKey);
                ResultData = engine.ProcessBlock(cipherData, 0, cipherData.Length);
            }
            catch (Exception ex)
            {
                throw ex;

            }
            return ResultData;
        }
        #endregion
        #region 公钥加密
        /// <summary>
        /// 公钥加密
        /// </summary>
        /// <returns>密文</returns>
        public static byte[] Encrypt(string publicKeyStr, byte[] plainTextData)
        {
            AsymmetricKeyParameter publicKey = GetPublicKeyParameter(publicKeyStr);
            //解密  
            byte[] ResultData = Encrypt(publicKey, plainTextData);
            return ResultData;
        }
        #endregion
        #region 公钥加密
        /// <summary>
        /// 公钥加密
        /// </summary>
        /// <returns>密文</returns>
        public static byte[] Encrypt(AsymmetricKeyParameter publicKey, byte[] plainTextData)
        {
            //非对称加密算法，加解密用  
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());
            //解密  
            byte[] ResultData = null;
            try
            {
                engine.Init(true, publicKey);
                ResultData = engine.ProcessBlock(plainTextData, 0, plainTextData.Length);
            }
            catch (Exception ex)
            {
                throw ex;

            }
            return ResultData;
        }
        #endregion
        #region 公钥验签
        /// <summary>
        /// 公钥验签
        /// </summary>
        /// <returns>验证结果</returns>
        public static bool DoCheck(byte[] content, byte[] sign, string publicKeyStr)
        {

            AsymmetricKeyParameter publicKey = GetPublicKeyParameter(publicKeyStr);
            return DoCheck(content, sign, publicKey);
        }
        #endregion
        #region 公钥验签
        /// <summary>
        /// 公钥验签
        /// </summary>
        /// <returns>验证结果</returns>
        public static bool DoCheck(byte[] content, byte[] sign, AsymmetricKeyParameter publicKey)
        {
            Org.BouncyCastle.Crypto.Digests.Sha1Digest sha1 = new Org.BouncyCastle.Crypto.Digests.Sha1Digest();
            //签名
            RsaDigestSigner signer = new RsaDigestSigner(sha1);
            signer.Init(false, publicKey);
            signer.BlockUpdate(content, 0, content.Length);
            bool flag = signer.VerifySignature(sign);
            return flag;
        }
        #endregion
        #region 私钥签名
        /// <summary>
        /// 私钥签名
        /// </summary>
        /// <returns>签名</returns>
        public static byte[] Sign(byte[] content, string privateKeyStr)
        {

            AsymmetricKeyParameter privateKey = GetPrivateKeyParameter(privateKeyStr);
            return Sign(content, privateKey);
        }
        #endregion
        #region 私钥签名
        /// <summary>
        /// 私钥签名
        /// </summary>
        /// <returns>签名</returns>
        public static byte[] Sign(byte[] content, AsymmetricKeyParameter privateKey)
        {
            Org.BouncyCastle.Crypto.Digests.Sha1Digest sha1 = new Org.BouncyCastle.Crypto.Digests.Sha1Digest();
            //签名
            RsaDigestSigner signer = new RsaDigestSigner(sha1);
            signer.Init(true, privateKey);
            signer.BlockUpdate(content, 0, content.Length);
            byte[] sign = signer.GenerateSignature();
            signer.Reset();
            return sign;
        }
        #endregion
    }
}
