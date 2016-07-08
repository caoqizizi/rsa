package com.caoqi.rsa.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/** 
 * RSA算法，实现数据的加密解密。 
 */
public class RSAUtil {
	private static Cipher cipher;  
    
    static{  
        try {  
            cipher = Cipher.getInstance("RSA");  
        } catch (NoSuchAlgorithmException e) {  
            e.printStackTrace();  
        } catch (NoSuchPaddingException e) {  
            e.printStackTrace();  
        }  
    }
    
    /** 
     * 生成密钥对 
     * @param filePath 生成密钥的路径 
     * @return 
     */  
    public static Map<String,String> generateKeyPair(String filePath){  
        try {  
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");  
            // 密钥位数  
            keyPairGen.initialize(2048);  
            // 密钥对  
            KeyPair keyPair = keyPairGen.generateKeyPair();  
            // 公钥  
            PublicKey publicKey = keyPair.getPublic();  
            // 私钥  
            PrivateKey privateKey = keyPair.getPrivate();  
            //得到公钥字符串  
            String publicKeyString = getKeyString(publicKey);  
            //得到私钥字符串  
            String privateKeyString = getKeyString(privateKey);  
            //将密钥对写入到文件  
            FileWriter pubfw = new FileWriter(filePath + "/publicKey.keystore");  
            FileWriter prifw = new FileWriter(filePath + "/privateKey.keystore");  
            BufferedWriter pubbw = new BufferedWriter(pubfw);  
            BufferedWriter pribw = new BufferedWriter(prifw);  
            pubbw.write(publicKeyString);  
            pribw.write(privateKeyString);  
            pubbw.flush();  
            pubbw.close();  
            pubfw.close();  
            pribw.flush();  
            pribw.close();  
            prifw.close();  
            //将生成的密钥对返回  
            Map<String,String> map = new HashMap<String,String>();  
            map.put("publicKey", publicKeyString);  
            map.put("privateKey", privateKeyString);  
            return map;  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        return null;  
    }
    
    /** 
     * 得到公钥 
     *  
     * @param key 
     *            密钥字符串（经过base64编码） 
     * @throws Exception 
     */  
    public static PublicKey getPublicKey(String key) throws Exception {  
        byte[] keyBytes;  
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);  
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);  
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
        PublicKey publicKey = keyFactory.generatePublic(keySpec);  
        return publicKey;  
    }  
      
    /** 
     * 得到私钥 
     *  
     * @param key 
     *            密钥字符串（经过base64编码） 
     * @throws Exception 
     */  
    public static PrivateKey getPrivateKey(String key) throws Exception {  
        byte[] keyBytes;  
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);  
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);  
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);  
        return privateKey;  
    }
    
    /** 
     * 得到密钥字符串（经过base64编码） 
     *  
     * @return 
     */  
    public static String getKeyString(Key key) throws Exception {  
        byte[] keyBytes = key.getEncoded();  
        String s = (new BASE64Encoder()).encode(keyBytes);  
        return s;  
    }
    
    /** 
     * 使用公钥对明文进行加密，返回BASE64编码的字符串 
     * @param publicKey 
     * @param plainText 
     * @return 
     */  
    public static String encrypt(PublicKey publicKey, String plainText){  
        try {             
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
            byte[] enBytes = cipher.doFinal(plainText.getBytes());            
            return (new BASE64Encoder()).encode(enBytes);  
        } catch (InvalidKeyException e) {  
            e.printStackTrace();  
        } catch (IllegalBlockSizeException e) {  
            e.printStackTrace();  
        } catch (BadPaddingException e) {  
            e.printStackTrace();  
        }  
        return null;  
    }  
      
    /** 
     * 使用keystore对明文进行加密 
     * @param publicKeystore 公钥文件路径 
     * @param plainText      明文 
     * @return 
     */  
    public static String fileEncrypt(String publicKeystore, String plainText){  
        try {             
            FileReader fr = new FileReader(publicKeystore);  
            BufferedReader br = new BufferedReader(fr);  
            String publicKeyString="";  
            String str;  
            while((str=br.readLine())!=null){  
                publicKeyString+=str;  
            }  
            br.close();  
            fr.close();  
            cipher.init(Cipher.ENCRYPT_MODE,getPublicKey(publicKeyString));  
            byte[] enBytes = cipher.doFinal(plainText.getBytes());            
            return (new BASE64Encoder()).encode(enBytes);  
        } catch (InvalidKeyException e) {  
            e.printStackTrace();  
        } catch (IllegalBlockSizeException e) {  
            e.printStackTrace();  
        } catch (BadPaddingException e) {  
            e.printStackTrace();  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        return null;  
    }
    
    /** 
     * 使用公钥对明文进行加密 
     * @param publicKey      公钥 
     * @param plainText      明文 
     * @return 
     */  
    public static String encrypt(String publicKey, String plainText){  
        try {              
            cipher.init(Cipher.ENCRYPT_MODE,getPublicKey(publicKey));  
            byte[] enBytes = cipher.doFinal(plainText.getBytes());            
            return (new BASE64Encoder()).encode(enBytes);  
        } catch (InvalidKeyException e) {  
            e.printStackTrace();  
        } catch (IllegalBlockSizeException e) {  
            e.printStackTrace();  
        } catch (BadPaddingException e) {  
            e.printStackTrace();  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        return null;  
    } 
      
    /** 
     * 使用私钥对明文密文进行解密 
     * @param privateKey 
     * @param enStr 
     * @return 
     */  
    public static String decrypt(PrivateKey privateKey, String enStr){  
        try {  
            cipher.init(Cipher.DECRYPT_MODE, privateKey);  
            byte[] deBytes = cipher.doFinal((new BASE64Decoder()).decodeBuffer(enStr));  
            return new String(deBytes);  
        } catch (InvalidKeyException e) {  
            e.printStackTrace();  
        } catch (IllegalBlockSizeException e) {  
            e.printStackTrace();  
        } catch (BadPaddingException e) {  
            e.printStackTrace();  
        } catch (IOException e) {  
            e.printStackTrace();  
        }  
        return null;  
    }
    
    /** 
     * 使用私钥对密文进行解密 
     * @param privateKey       私钥 
     * @param enStr            密文 
     * @return 
     */  
    public static String decrypt(String privateKey, String enStr){  
        try {           
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));  
            byte[] deBytes = cipher.doFinal((new BASE64Decoder()).decodeBuffer(enStr));  
            return new String(deBytes);  
        } catch (InvalidKeyException e) {  
            e.printStackTrace();  
        } catch (IllegalBlockSizeException e) {  
            e.printStackTrace();  
        } catch (BadPaddingException e) {  
            e.printStackTrace();  
        } catch (IOException e) {  
            e.printStackTrace();  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        return null;  
    }
    
    /** 
     * 使用keystore对密文进行解密 
     * @param privateKeystore  私钥路径 
     * @param enStr            密文 
     * @return 
     */  
    public static String fileDecrypt(String privateKeystore, String enStr){  
        try {  
            FileReader fr = new FileReader(privateKeystore);  
            BufferedReader br = new BufferedReader(fr);  
            String privateKeyString="";  
            String str;  
            while((str=br.readLine())!=null){  
                privateKeyString+=str;  
            }  
            br.close();  
            fr.close();           
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKeyString));  
            byte[] deBytes = cipher.doFinal((new BASE64Decoder()).decodeBuffer(enStr));  
            return new String(deBytes);  
        } catch (InvalidKeyException e) {  
            e.printStackTrace();  
        } catch (IllegalBlockSizeException e) {  
            e.printStackTrace();  
        } catch (BadPaddingException e) {  
            e.printStackTrace();  
        } catch (IOException e) {  
            e.printStackTrace();  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        return null;  
    }
    
    public static void main(String[] args) {
//    	generateKeyPair("D:/RSA");
    	
    	String publicKey; 
    	String privateKey;

    	publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviSuCu4Yg/WAyjp06qiaE/ioI2M/ACT9UTUVxWtM7IZlXMQZPjLn0H1x0zmJ/VLIhnBliyb06QLvtrrBFRt4jnOJR5LjoTg/g8XYdVXN6a+XFjqFvOUPgzZ7OdywOoXxiO+M7WrvT0XgqyBqCnDADpY1eucDqfIDYYOBHKbtMkh0N4ZVBcfULb1Sm+Q7ed+jUa8eXPQPhMrWvhQkIeZJh+hCIrNjXUxyfZPh1tSvqoJYArbyHZs8LnbUtjIQCx9OlR9+xJTx3L9h89I4D+hqA4CZqxUzfibsu5XgYKnoSri2OCR2FefSfYlCd8Fysp0wET/r1L141qnhoMQtrUs8jwIDAQAB";
    	privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+JK4K7hiD9YDKOnTqqJoT+KgjYz8AJP1RNRXFa0zshmVcxBk+MufQfXHTOYn9UsiGcGWLJvTpAu+2usEVG3iOc4lHkuOhOD+Dxdh1Vc3pr5cWOoW85Q+DNns53LA6hfGI74ztau9PReCrIGoKcMAOljV65wOp8gNhg4Ecpu0ySHQ3hlUFx9QtvVKb5Dt536NRrx5c9A+Eyta+FCQh5kmH6EIis2NdTHJ9k+HW1K+qglgCtvIdmzwudtS2MhALH06VH37ElPHcv2Hz0jgP6GoDgJmrFTN+Juy7leBgqehKuLY4JHYV59J9iUJ3wXKynTARP+vUvXjWqeGgxC2tSzyPAgMBAAECggEAMhFkhtpFOFIoFJgp+zRkRgf+9jqG91nGHmEVF4P2oH2PKUs1vmwXII43r8AB9uOai9QC2Q5sBQNR7dLlTtKJ/zCrIF6sc+JkzyUEp3jtnLAw35iPaLsER6/L6OOUwARPIpi5ijbTRxOGYmlJovAnkm+5K2CzVUe13jKLh+joool/ReZk0Rsr4tVLSLmvzDA/sRwYun0x0+jl5EZSQfwsVyN9bD5rY/In/EuvH9yj5R4lPe+mimF4Os6IgTsP5LzqDTAiFx5NNioFRJ2SkcTmM0CZQeMIBuvvF2HCtJlDEfCytD7wYup3GBvar2ccOe9T3YhJdsj5bfAJHVJtamxQwQKBgQDnYReMMzqAh2HOFL8QymzOjImsrOz6NCZatq38TU1hSe9PK+C0sFGhkd788y4AuURS1Btu4i7F+hOYcj1z3L+NSPGE3yLHVjakMrrNbA9rwG/t7oU0cG7d0WWM9bcTQiCSNcUyt69BGH3dZdqee1tITzqghE7+gh9RYiVcI6/8LwKBgQDSYEuWFLMUsR/s7unSHCucuEXjwbYrvknv8Y81sjvrWktNXrJoYlbGy/7HYA6lxzchtSxhPuUSjopwQ5scgMhqf8Gxz7jsDN9ak2dErF7cWRFYfh6aKhkbEw9oG01jIX15MK0TbMafoJslDhPQF1cP9i0+ZGg+gPbASdeUVRTNoQKBgQCOjwDOLgYeiMtXCOtL8hymCmsNDCKaaiUzgRijuhEyHzamJhe13Gj/TnwAh+hRI9UX333jjNJawqDuLXz1dQ5Eg6vjPQQVo2XZNzRnOuwpbJDKHUrPK3Lzkn+qIP6ii/y7eQu+GvSM/AUYsxfGy6RLYh1yJvLw1sVrBDiWk5prmwKBgFvgrmI3XBa3XKgPl5KptupVGEDmAveLvaLLLq5WzxB0eNqrduNbv2ZHBVhxvTPtk0hnZaB65XR7SD7LZ9zE6cKJVUCg5bRB0vIt2jYFydAWHhs1yYuuwxQt+NaQxfV7VN8uwQfww7ZHYDqIsWJ6Lw3Lh+rt0xEpJZrJJRulJNbBAoGBAK1OEnfBpSB99N8gdhp+ZGLsDfwFCQ2Cd4Jpsd4hxdwbXevNuA1OiE20sHPuKqEqfOKocgTMobCwbSfnymatRydVoeUumkEc4Ja+XDgH+P1eXQLdIuRCwh0AXl+vkuOCBDMw367Zp/j6vwPlNKh9ZmOBPwhV0Syv2Z8uGkTZ6g+f";
    	
    	
    	System.err.println("公钥加密——私钥解密");
        String source = "高可用架构对于互联网服务基本是标配。";
        System.out.println("\r加密前文字：\r\n" + source);
        String aData = RSAUtil.encrypt(publicKey, source);
        System.out.println("加密后文字：\r\n" + aData);
        String dData = RSAUtil.decrypt(privateKey, aData);
        System.out.println("解密后文字: \r\n" + dData);  	
	}
}
