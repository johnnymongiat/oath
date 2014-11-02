package com.lochbridge.oath.otp;

import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableSet;

/**
 * Provides RFC 6238 test vectors used for the HOTP time-based variant algorithm interoperability test.
 * @see https://tools.ietf.org/html/rfc6238#appendix-B
 */
public final class RFC6238TestVectors {
	
	/**
	 * Represents an RFC 6238 test vector including the expected TOTP.
	 */
	public static final class TestVector {
		
		private final String totp;
		private final long testTime;
		private final HmacShaAlgorithm algorithm;
		private final long timeStep = TimeUnit.SECONDS.toMillis(30);
		private final int digits = 8;
		private final byte[] key;
		
		private TestVector(String totp, long testTime, HmacShaAlgorithm algorithm, byte[] key) {
			this.totp = totp;
			this.testTime = TimeUnit.SECONDS.toMillis(testTime);
			this.algorithm = algorithm;
			this.key = new byte[key.length];
			System.arraycopy(key, 0, this.key, 0, key.length);
		}

		/**
		 * Returns the {@link HmacShaAlgorithm} used in generating the expected TOTP.
		 * @return the {@link HmacShaAlgorithm} used in generating the expected TOTP.
		 */
		public HmacShaAlgorithm getAlgorithm() {
			return algorithm;
		}

		/**
		 * Returns the number of digits used in generating the expected TOTP.
		 * @return the number of digits used in generating the expected TOTP.
		 */
		public int getDigits() {
			return digits;
		}

		/**
		 * Returns the shared secret key used in generating the expected TOTP.
		 * @return the shared secret key used in generating the expected TOTP.
		 */
		public byte[] getKey() {
			return key;
		}

		/**
		 * Returns the time step size used in generating the expected TOTP.
		 * @return the time step size used in generating the expected TOTP.
		 */
		public long getTimeStep() {
			return timeStep;
		}

		/**
		 * Returns the expected TOTP value.
		 * @return the expected TOTP value.
		 */
		public String getTotp() {
			return totp;
		}

		/**
		 * Returns the test time (in milliseconds) used in generating the expected TOTP.
		 * @return the test time (in milliseconds) used in generating the expected TOTP.
		 */
		public long getTestTime() {
			return testTime;
		}
		
	}
	
	/** The test shared secret key used for TOTP based on HMAC-SHA-1. */
	public static final byte[] KEY_FOR_HMAC_SHA_1 = "12345678901234567890".getBytes(Charsets.US_ASCII);
	
	/** The test shared secret key (Base 32 encoded) used for TOTP based on HMAC-SHA-256. */
	public static final byte[] KEY_FOR_HMAC_SHA_256 = "12345678901234567890123456789012".getBytes(Charsets.US_ASCII);
	
	/** The test shared secret key (Base 32 encoded) used for TOTP based on HMAC-SHA-512. */
	public static final byte[] KEY_FOR_HMAC_SHA_512 = "1234567890123456789012345678901234567890123456789012345678901234".getBytes(Charsets.US_ASCII);
	
	/** The times (in seconds) used in generating the TOTP test cases. */
	private static final long[] TEST_TIME_SECONDS = { 59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L };
	
	/** Set of expected TOTP test case data. */
	public static final Set<TestVector> TEST_VECTORS = ImmutableSet.<TestVector>builder()
			.add(new TestVector("94287082", TEST_TIME_SECONDS[0], HmacShaAlgorithm.HMAC_SHA_1, KEY_FOR_HMAC_SHA_1))
			.add(new TestVector("46119246", TEST_TIME_SECONDS[0], HmacShaAlgorithm.HMAC_SHA_256, KEY_FOR_HMAC_SHA_256))
			.add(new TestVector("90693936", TEST_TIME_SECONDS[0], HmacShaAlgorithm.HMAC_SHA_512, KEY_FOR_HMAC_SHA_512))
			.add(new TestVector("07081804", TEST_TIME_SECONDS[1], HmacShaAlgorithm.HMAC_SHA_1, KEY_FOR_HMAC_SHA_1))
			.add(new TestVector("68084774", TEST_TIME_SECONDS[1], HmacShaAlgorithm.HMAC_SHA_256, KEY_FOR_HMAC_SHA_256))
			.add(new TestVector("25091201", TEST_TIME_SECONDS[1], HmacShaAlgorithm.HMAC_SHA_512, KEY_FOR_HMAC_SHA_512))
			.add(new TestVector("14050471", TEST_TIME_SECONDS[2], HmacShaAlgorithm.HMAC_SHA_1, KEY_FOR_HMAC_SHA_1))
			.add(new TestVector("67062674", TEST_TIME_SECONDS[2], HmacShaAlgorithm.HMAC_SHA_256, KEY_FOR_HMAC_SHA_256))
			.add(new TestVector("99943326", TEST_TIME_SECONDS[2], HmacShaAlgorithm.HMAC_SHA_512, KEY_FOR_HMAC_SHA_512))
			.add(new TestVector("89005924", TEST_TIME_SECONDS[3], HmacShaAlgorithm.HMAC_SHA_1, KEY_FOR_HMAC_SHA_1))
			.add(new TestVector("91819424", TEST_TIME_SECONDS[3], HmacShaAlgorithm.HMAC_SHA_256, KEY_FOR_HMAC_SHA_256))
			.add(new TestVector("93441116", TEST_TIME_SECONDS[3], HmacShaAlgorithm.HMAC_SHA_512, KEY_FOR_HMAC_SHA_512))
			.add(new TestVector("69279037", TEST_TIME_SECONDS[4], HmacShaAlgorithm.HMAC_SHA_1, KEY_FOR_HMAC_SHA_1))
			.add(new TestVector("90698825", TEST_TIME_SECONDS[4], HmacShaAlgorithm.HMAC_SHA_256, KEY_FOR_HMAC_SHA_256))
			.add(new TestVector("38618901", TEST_TIME_SECONDS[4], HmacShaAlgorithm.HMAC_SHA_512, KEY_FOR_HMAC_SHA_512))
			.add(new TestVector("65353130", TEST_TIME_SECONDS[5], HmacShaAlgorithm.HMAC_SHA_1, KEY_FOR_HMAC_SHA_1))
			.add(new TestVector("77737706", TEST_TIME_SECONDS[5], HmacShaAlgorithm.HMAC_SHA_256, KEY_FOR_HMAC_SHA_256))
			.add(new TestVector("47863826", TEST_TIME_SECONDS[5], HmacShaAlgorithm.HMAC_SHA_512, KEY_FOR_HMAC_SHA_512))
			.build();
	
	private RFC6238TestVectors() {
		// prevent instantiation
	}

}
