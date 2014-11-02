package com.lochbridge.oath.otp;

import java.util.Set;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableSet;

/**
 * Provides RFC 4226 test vectors used for the HOTP HMAC-based variant algorithm interoperability test.
 * @see http://tools.ietf.org/html/rfc4226#appendix-D
 */
public final class RFC4226TestVectors {
	
	/**
	 * Represents an RFC 4226 test vector including the expected HOTP.
	 */
	public static final class TestVector {
		
		private final String hotp;
		private final long movingFactor;
		private final int digits = 6;
		private final byte[] key;
		
		private TestVector(String hotp, long movingFactor, byte[] key) {
			this.hotp = hotp;
			this.movingFactor = movingFactor;
			this.key = new byte[key.length];
			System.arraycopy(key, 0, this.key, 0, key.length);
		}

		/**
		 * Returns the number of digits used in generating the expected HOTP.
		 * @return the number of digits used in generating the expected HOTP.
		 */
		public int getDigits() {
			return digits;
		}

		/**
		 * Returns the shared secret key used in generating the expected HOTP.
		 * @return the shared secret key used in generating the expected HOTP.
		 */
		public byte[] getKey() {
			return key;
		}

		/**
		 * Returns the moving factor used in generating the expected HOTP.
		 * @return the moving factor used in generating the expected HOTP.
		 */
		public long getMovingFactor() {
			return movingFactor;
		}

		/**
		 * Returns the expected HOTP value.
		 * @return the expected HOTP value.
		 */
		public String getHotp() {
			return hotp;
		}
		
	}
	
	/** The test shared secret key. */
	public static final byte[] KEY = "12345678901234567890".getBytes(Charsets.US_ASCII);
	
	/** Set of expected TOTP test case data. */
	public static final Set<TestVector> TEST_VECTORS = ImmutableSet.<TestVector>builder()
			.add(new TestVector("755224", 0, KEY))
			.add(new TestVector("287082", 1, KEY))
			.add(new TestVector("359152", 2, KEY))
			.add(new TestVector("969429", 3, KEY))
			.add(new TestVector("338314", 4, KEY))
			.add(new TestVector("254676", 5, KEY))
			.add(new TestVector("287922", 6, KEY))
			.add(new TestVector("162583", 7, KEY))
			.add(new TestVector("399871", 8, KEY))
			.add(new TestVector("520489", 9, KEY))
			.build();
	
	private RFC4226TestVectors() {
		// prevent instantiation
	}

}
