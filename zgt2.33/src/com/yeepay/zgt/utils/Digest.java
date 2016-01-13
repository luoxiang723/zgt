package com.yeepay.zgt.utils;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.commons.lang.StringUtils;

/**
 * hmac???ç­¾å??ç®?ï¿??
 * 
 * @author blakeyuan
 *
 */
public class Digest {
	public static final String ENCODE = "UTF-8"; // UTF-8

	/**
	 * ??´æ?¥ç??MD5ç­¾å??å¯¹æ?°æ??ç­¾å??ï¼?ä¸????è¦?å¯?ï¿??
	 * 
	 * @param aValue
	 * @return
	 */
	public static String signMD5(String aValue, String encoding) {
		try {
			byte[] input = aValue.getBytes(encoding);
			MessageDigest md = MessageDigest.getInstance("MD5");
			return ConvertUtils.toHex(md.digest(input));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * ??´æ?¥ç??MD5ç­¾å??å¯¹æ?°æ??ç­¾å??ï¼?ä¸????è¦?å¯?ï¿??
	 * 
	 * @param aValue
	 * @return
	 */
	public static String hmacSign(String aValue) {
		try {
			byte[] input = aValue.getBytes();
			MessageDigest md = MessageDigest.getInstance("MD5");
			return ConvertUtils.toHex(md.digest(input));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * tao.wu 2012-09-06 ??´æ?¥ç??MD5ç­¾å??å¯¹æ?°æ??ç­¾å??ï¼?ä¸????è¦?å¯?ï¿??ä½¿ç?¨æ??å®?ç¼????)
	 * 
	 * @param aValue
	 * @return
	 */
	public static String hmacSignWithCharset(String aValue, String charset) {
		try {
			byte[] input = null;
			if (StringUtils.isBlank(charset)) {
				input = aValue.getBytes();
			} else {
				input = aValue.getBytes(charset);
			}
			MessageDigest md = MessageDigest.getInstance("MD5");
			return ConvertUtils.toHex(md.digest(input));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * å¯¹æ?¥æ??è¿?è¡?hmacç­¾å??ï¼?å­?ç¬?ä¸²æ?????UTF-8ç¼????
	 * 
	 * @param aValue
	 *            - å­?ç¬?ï¿??
	 * @param aKey
	 *            - å¯????
	 * @return - ç­¾å??ç»????ï¼?hexå­?ç¬?ï¿??
	 */
	public static String hmacSign(String aValue, String aKey) {
		return hmacSign(aValue, aKey, ENCODE);
	}

	/**
	 * å¯¹æ?¥æ??è¿?è¡???????MD5è¿?è¡?hmacç­¾å??
	 * 
	 * @param aValue
	 *            - å­?ç¬?ï¿??
	 * @param aKey
	 *            - å¯????
	 * @param encoding
	 *            - å­?ç¬?ä¸²ç???????¹ï¿½?
	 * @return - ç­¾å??ç»????ï¼?hexå­?ç¬?ï¿??
	 */
	public static String hmacSign(String aValue, String aKey, String encoding) {
		byte k_ipad[] = new byte[64];
		byte k_opad[] = new byte[64];
		byte keyb[];
		byte value[];
		try {
			keyb = aKey.getBytes(encoding);
			value = aValue.getBytes(encoding);
		} catch (UnsupportedEncodingException e) {
			keyb = aKey.getBytes();
			value = aValue.getBytes();
		}
		Arrays.fill(k_ipad, keyb.length, 64, (byte) 54);
		Arrays.fill(k_opad, keyb.length, 64, (byte) 92);
		for (int i = 0; i < keyb.length; i++) {
			k_ipad[i] = (byte) (keyb[i] ^ 0x36);
			k_opad[i] = (byte) (keyb[i] ^ 0x5c);
		}

		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		md.update(k_ipad);
		md.update(value);
		byte dg[] = md.digest();
		md.reset();
		md.update(k_opad);
		md.update(dg, 0, 16);
		dg = md.digest();
		return ConvertUtils.toHex(dg);
	}

	/**
	 * å¯¹æ?¥æ??è¿?è¡???????SHAè¿?è¡?hmacç­¾å??
	 * 
	 * @param aValue
	 *            - å­?ç¬?ï¿??
	 * @param aKey
	 *            - å¯????
	 * @param encoding
	 *            - å­?ç¬?ä¸²ç???????¹ï¿½?
	 * @return - ç­¾å??ç»????ï¼?hexå­?ç¬?ï¿??
	 */
	public static String hmacSHASign(String aValue, String aKey, String encoding) {
		byte k_ipad[] = new byte[64];
		byte k_opad[] = new byte[64];
		byte keyb[];
		byte value[];
		try {
			keyb = aKey.getBytes(encoding);
			value = aValue.getBytes(encoding);
		} catch (UnsupportedEncodingException e) {
			keyb = aKey.getBytes();
			value = aValue.getBytes();
		}
		Arrays.fill(k_ipad, keyb.length, 64, (byte) 54);
		Arrays.fill(k_opad, keyb.length, 64, (byte) 92);
		for (int i = 0; i < keyb.length; i++) {
			k_ipad[i] = (byte) (keyb[i] ^ 0x36);
			k_opad[i] = (byte) (keyb[i] ^ 0x5c);
		}

		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		md.update(k_ipad);
		md.update(value);
		byte dg[] = md.digest();
		md.reset();
		md.update(k_opad);
		md.update(dg, 0, 20);
		dg = md.digest();
		return ConvertUtils.toHex(dg);
	}

	/**
	 * å¯¹æ?¥æ??è¿?è¡?SHAç­¾å??
	 * 
	 * @param aValue
	 *            - å¾?ç­¾å?????å­?ç¬?ä¸²ï??ç¼????ï¼?UTF-8ï¿??
	 * @return - ç­¾å??ç»????ï¼?hexå­?ç¬?ï¿??
	 */
	public static String digest(String aValue) {
		return digest(aValue, ENCODE);

	}

	/**
	 * å¯¹æ?¥æ??è¿?è¡?SHAç­¾å??
	 * 
	 * @param aValue
	 *            - å¾?ç­¾å?????å­?ç¬?ï¿??
	 * @param encoding
	 *            - å­?ç¬?ä¸²ç???????¹ï¿½?
	 * @return - ç­¾å??ç»????ï¼?hexå­?ç¬?ï¿??
	 */
	public static String digest(String aValue, String encoding) {
		aValue = aValue.trim();
		byte value[];
		try {
			value = aValue.getBytes(encoding);
		} catch (UnsupportedEncodingException e) {
			value = aValue.getBytes();
		}
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		return ConvertUtils.toHex(md.digest(value));
	}

	/**
	 * å¯¹å??ç¬?ä¸²è??è¡?ç­¾å??
	 * 
	 * @param aValue
	 *            - å¾?ç­¾å??å­?ç¬?ä¸?
	 * @param alg
	 *            - ç­¾å??ç®?æ³????ç§°ï??å¦?SHA, MD5ç­?ï¼?
	 * @param encoding
	 *            - å­?ç¬?ä¸²ç???????¹ï¿½?
	 * @return - ç­¾å??ç»????ï¼?hexå­?ç¬?ï¿??
	 */
	public static String digest(String aValue, String alg, String encoding) {
		aValue = aValue.trim();
		byte value[];
		try {
			value = aValue.getBytes(encoding);
		} catch (UnsupportedEncodingException e) {
			value = aValue.getBytes();
		}
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance(alg);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		return ConvertUtils.toHex(md.digest(value));
	}

	public static String udpSign(String aValue) {
		try {
			byte[] input = aValue.getBytes("UTF-8");
			MessageDigest md = MessageDigest.getInstance("SHA1");
			return new String(Base64.encode(md.digest(input)), ENCODE);
		} catch (Exception e) {
			return null;
		}
	}

}
