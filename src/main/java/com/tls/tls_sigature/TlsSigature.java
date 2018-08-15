package com.tls.tls_sigature;

import com.alibaba.fastjson.JSONObject;
import com.tls.base64_url.base64_url;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.Arrays;

import java.io.CharArrayReader;
import java.io.IOException;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Base64;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class TlsSigature {
    public static class GenTLSSignatureResult {
        public String errMessage;
        public String urlSig;
        public int expireTime;
        public int initTime;

        GenTLSSignatureResult() {
            errMessage = "";
            urlSig = "";
        }
    }

    public static class CheckTLSSignatureResult {
        public String errMessage;
        public boolean verifyResult;
        public int expireTime;
        public int initTime;

        CheckTLSSignatureResult() {
            errMessage = "";
            verifyResult = false;
        }
    }

    public static void main(String[] args) throws UnsupportedEncodingException, DataFormatException {
        try {
            //Use pemfile keys to test
            String privStr = "-----BEGIN PRIVATE KEY-----\n" +
                    "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgiBPYMVTjspLfqoq46oZd\n" +
                    "j9A0C8p7aK3Fi6/4zLugCkehRANCAATU49QhsAEVfIVJUmB6SpUC6BPaku1g/dzn\n" +
                    "0Nl7iIY7W7g2FoANWnoF51eEUb6lcZ3gzfgg8VFGTpJriwHQWf5T\n" +
                    "-----END PRIVATE KEY-----";

            //change public pem string to public string
            String pubStr = "-----BEGIN PUBLIC KEY-----\n" +
                    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE1OPUIbABFXyFSVJgekqVAugT2pLtYP3c\n" +
                    "59DZe4iGO1u4NhaADVp6BedXhFG+pXGd4M34IPFRRk6Sa4sB0Fn+Uw==\n" +
                    "-----END PUBLIC KEY-----";

            // generate signature
            GenTLSSignatureResult result = genTLSSignature("1400000955", "xiaojun", 0, privStr, true);
            System.out.println(result.urlSig.length());
            if (0 == result.urlSig.length()) {
                System.out.println("GenTLSSignatureEx failed: " + result.errMessage);
                return;
            }

            System.out.println("---\ngenerate sig:\n" + result.urlSig + "\n---\n");

            // check signature
            CheckTLSSignatureResult checkResult = checkTLSSignature(result.urlSig, "1400000955", "xiaojun", 0, pubStr, true);
            if (!checkResult.verifyResult) {
                System.out.println("checkTLSSignature failed: " + result.errMessage);
                return;
            }

            System.out.println("\n---\ncheck sig ok -- expire time " + checkResult.expireTime + " -- init time " + checkResult.initTime + "\n---\n");
        } catch (Exception e) {
            e.printStackTrace();
        }


        // Encode a String into bytes
        String inputString = "blahblahblah??";
        byte[] input = inputString.getBytes("UTF-8");

        // Compress the bytes
        byte[] output = new byte[100];
        Deflater compresser = new Deflater();
        compresser.setInput(input);
        compresser.finish();
        int compressedDataLength = compresser.deflate(output);

        // Decompress the bytes
        Inflater decompresser = new Inflater();
        decompresser.setInput(output, 0, compressedDataLength);
        byte[] result = new byte[100];
        int resultLength = decompresser.inflate(result);
        decompresser.end();

        // Decode the bytes into a String
        String outputString = new String(result, 0, resultLength, "UTF-8");
    }


    public static GenTLSSignatureResult genTLSSignature(String appId,
                                                        String identifier, long accountType,
                                                        String privStr, boolean sandBox) throws IOException {
        return genTLSSignature(3600 * 24 * 180, appId, identifier, accountType, privStr, sandBox);
    }

    /**
     * @param expire      有效期，单位是秒，推荐一个月
     * @param appId       应用的 appId
     * @param identifier  用户 id
     * @param accountType 创建应用后在配置页面上展示的 acctype
     * @param privStr     生成 tls 票据使用的私钥内容
     * @return 如果出错，GenTLSSignatureResult 中的 urlSig为空，errMsg 为出错信息，成功返回有效的票据
     * @throws IOException e
     * @brief 生成 tls 票据
     */
    public static GenTLSSignatureResult genTLSSignature(long expire, String appId,
                                                        String identifier, long accountType,
                                                        String privStr, boolean sandBox) throws IOException {

        long appIdLong = Long.parseLong(appId);
        if (sandBox) {
            accountType = 0;
            appId = "0";
        }

        PrivateKey privKeyStruct = getPrivateKey(privStr);

        //Create Json string and serialization String
        String jsonString = "{"
                + "\"TLS.account_type\":\"" + accountType + "\","
                + "\"TLS.identifier\":\"" + identifier + "\","
                + "\"TLS.appid_at_3rd\":\"" + appId + "\","
                + "\"TLS.sdk_appid\":\"" + appIdLong + "\","
                + "\"TLS.expire_after\":\"" + expire + "\"";

        if (sandBox) {
            jsonString = jsonString + ",\"TLS.version\": \"201512300000\"";
        }

        jsonString = jsonString + "}";
        String time = String.valueOf(System.currentTimeMillis() / 1000);
        String serialString =
                "TLS.appid_at_3rd:" + appId + "\n" +
                        "TLS.account_type:" + accountType + "\n" +
                        "TLS.identifier:" + identifier + "\n" +
                        "TLS.sdk_appid:" + appIdLong + "\n" +
                        "TLS.time:" + time + "\n" +
                        "TLS.expire_after:" + expire + "\n";

        return getResult(privKeyStruct, serialString, jsonString, time);
    }

    /**
     * @param urlSig      返回 tls 票据
     * @param appId       应的 appId
     * @param identifier  用户 id
     * @param accountType 创建应用后在配置页面上展示的 acctype
     * @param publicKey   用于校验 tls 票据的公钥内容，但是需要先将公钥文件转换为 java 原生 api 使用的格式，下面是推荐的命令
     *                    openssl pkcs8 -topk8 -in ec_key.pem -outform PEM -out p8_priv.pem -nocrypt
     * @return 如果出错 CheckTLSSignatureResult 中的 verifyResult 为 false，错误信息在 errMsg，校验成功为 true
     * @throws DataFormatException e
     * @brief 校验 tls 票据
     */
    public static CheckTLSSignatureResult checkTLSSignature(String urlSig, String appId,
                                                            String identifier, long accountType,
                                                            String publicKey, boolean sandBox) throws DataFormatException {

        long appIdLong = Long.parseLong(appId);
        if (sandBox) {
            accountType = 0;
            appId = "0";
        }

        CheckTLSSignatureResult result = new CheckTLSSignatureResult();
        Security.addProvider(new BouncyCastleProvider());

        //DeBaseUrl64 urlSig to json
        byte[] decompressBytes = new byte[1024];
        int decompressLength = decompression(base64_url.base64DecodeUrl(urlSig.getBytes(Charset.forName("UTF-8"))), decompressBytes);

        String jsonString = new String(Arrays.copyOfRange(decompressBytes, 0, decompressLength));

        //Get TLS.Sig from json
        JSONObject jsonObject = JSONObject.parseObject(jsonString);
        String sigTLS = jsonObject.getString("TLS.sig");

        //debase64 TLS.Sig to get serailString
        byte[] signatureBytes = Base64.getDecoder().decode(sigTLS.getBytes(Charset.forName("UTF-8")));

        String sigTime = jsonObject.getString("TLS.time");
        String sigExpire = jsonObject.getString("TLS.expire_after");

        //checkTime
        if (System.currentTimeMillis() / 1000 - Long.parseLong(sigTime) > Long.parseLong(sigExpire)) {
            result.errMessage = "TLS sig is out of date ";
            return result;
        }

        //Get Serial String from json
        String serialString =
                "TLS.appid_at_3rd:" + appId + "\n" +
                        "TLS.account_type:" + accountType + "\n" +
                        "TLS.identifier:" + identifier + "\n" +
                        "TLS.sdk_appid:" + appIdLong + "\n" +
                        "TLS.time:" + sigTime + "\n" +
                        "TLS.expire_after:" + sigExpire + "\n";
        try {

            PublicKey pubKeyStruct = getPublicKey(publicKey);

            Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
            signature.initVerify(pubKeyStruct);
            signature.update(serialString.getBytes(Charset.forName("UTF-8")));
            result.verifyResult = signature.verify(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
            result.errMessage = "Failed in checking sig";
        }

        return result;
    }

    private static GenTLSSignatureResult getResult(PrivateKey privKeyStruct, String serialString, String jsonString, String time) {
        GenTLSSignatureResult result = new GenTLSSignatureResult();
        try {
            //Create Signature by serialString
            Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
            signature.initSign(privKeyStruct);
            signature.update(serialString.getBytes(Charset.forName("UTF-8")));
            byte[] signatureBytes = signature.sign();

            String sigTLS = Base64.getEncoder().encodeToString(signatureBytes);

            //Add TlsSig to jsonString
            JSONObject jsonObject = JSONObject.parseObject(jsonString);
            jsonObject.put("TLS.sig", sigTLS);
            jsonObject.put("TLS.time", time);
            jsonString = jsonObject.toString();

            byte[] compressBytes = new byte[512];
            int compressBytesLength = compress(jsonString.getBytes(Charset.forName("UTF-8")), compressBytes);

            result.urlSig = new String(base64_url.base64EncodeUrl(Arrays.copyOfRange(compressBytes, 0, compressBytesLength)));
        } catch (Exception e) {
            e.printStackTrace();
            result.errMessage = "generate usersig failed";
        }
        return result;
    }

    private static PrivateKey getPrivateKey(String privStr) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        Reader reader = new CharArrayReader(privStr.toCharArray());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PEMParser parser = new PEMParser(reader);
        Object obj = parser.readObject();
        parser.close();
        return converter.getPrivateKey((PrivateKeyInfo) obj);
    }

    private static PublicKey getPublicKey(String publicKey) throws IOException {
        Reader reader = new CharArrayReader(publicKey.toCharArray());
        PEMParser parser = new PEMParser(reader);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        Object obj = parser.readObject();
        parser.close();
        return converter.getPublicKey((SubjectPublicKeyInfo) obj);
    }

    /**
     * 解压字符串
     *
     * @param compressBytes   待解压字符数组
     * @param decompressBytes 新的字符数组
     * @return
     * @throws DataFormatException e
     */
    private static int decompression(byte[] compressBytes, byte[] decompressBytes) throws DataFormatException {
        //Decompression
        Inflater decompression = new Inflater();
        decompression.setInput(compressBytes, 0, compressBytes.length);
        int decompressLength = decompression.inflate(decompressBytes);
        decompression.end();
        return decompressLength;
    }

    /**
     * 压缩字符
     *
     * @param compressBytes   待压缩字符
     * @param decompressBytes 存放压缩后的数组
     * @return int
     */
    private static int compress(byte[] compressBytes, byte[] decompressBytes) {
        Deflater compresser = new Deflater();
        compresser.setInput(compressBytes);
        compresser.finish();
        int compressBytesLength = compresser.deflate(decompressBytes);
        compresser.end();
        return compressBytesLength;
    }
}
