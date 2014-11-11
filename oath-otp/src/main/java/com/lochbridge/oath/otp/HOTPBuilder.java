package com.lochbridge.oath.otp;

import java.lang.reflect.UndeclaredThrowableException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.Range;

/**
 * A HMAC-based One-time Password (HOTP) builder.
 * <p>
 * This is an implementation of the OATH HOTP algorithm as described by RFC
 * 4226. This implementation supports sequence/counter-based moving factors, and
 * numeric-only HOTP values ranging from size 6 to 8 (inclusive). Clients are
 * recommended to use a shared secret key length of 160 bits.
 * </p>
 * <p>
 * The builder, obtained via a call to the static {@code key(...)} method on
 * {@link HOTP}, provides methods for configuring the HOTP generation
 * parameters. Once the HOTP configuration is prepared, the builder is used to
 * generate an {@link HOTP} using the {@code build()} method:
 * </p>
 * 
 * <pre>
 * // We use the recommended 160-bit (20 bytes) length keys.
 * String sharedSecretKey = &quot;12345678901234567890&quot;;
 * byte[] key = sharedSecretKey.getBytes(&quot;US-ASCII&quot;);
 * 
 * // Generate a 6-digit HOTP using an arbitrary moving factor of 5.
 * HOTP hotp = HOTP.key(key).digits(6).movingFactor(5).build();
 * // prints &quot;254676&quot;
 * System.out.println(hotp.value());
 * </pre>
 *
 * @author Loren Hart
 * @author Johnny Mongiat
 * 
 * @see http://tools.ietf.org/html/rfc4226
 */
public final class HOTPBuilder {

    /** The default number of digits the HOTP value contains. */
    public static final int DEFAULT_DIGITS = 6;

    /** The minimum allowed number of digits the HOTP value can contain. */
    public static final int MIN_ALLOWED_DIGITS = 6;

    /** The maximum allowed number of digits the HOTP value can contain. */
    public static final int MAX_ALLOWED_DIGITS = 8;

    /** The shared secret key. */
    private final byte[] key;

    /** The moving factor (defaults to 0). */
    private long movingFactor = 0;

    /**
     * The number of digits the HOTP value contains (defaults to
     * {@link #DEFAULT_DIGITS}).
     */
    private int digits = DEFAULT_DIGITS;

    /**
     * Creates a new instance of {@code HOTPBuilder} initialized with a shared
     * secret key.
     * 
     * @param key
     *            the shared secret key. The contents of the array are copied to
     *            protect against subsequent modification.
     * 
     * @throws NullPointerException
     *             if {@code key} is {@code null}.
     */
    HOTPBuilder(byte[] key) {
        Preconditions.checkNotNull(key);
        this.key = new byte[key.length];
        System.arraycopy(key, 0, this.key, 0, key.length);
    }

    /**
     * Returns this {@code HOTPBuilder} instance initialized with the specified
     * {@code movingFactor}.
     * 
     * @param movingFactor
     *            the moving factor
     * 
     * @return this {@code HOTPBuilder} instance initialized with the specified
     *         {@code movingFactor}.
     * 
     * @throws IllegalArgumentException
     *             if {@code movingFactor} is < 0.
     */
    public HOTPBuilder movingFactor(long movingFactor) {
        Preconditions.checkArgument(movingFactor >= 0);
        this.movingFactor = movingFactor;
        return this;
    }

    /**
     * Returns this {@code HOTPBuilder} instance initialized with the specified
     * {@code digits}.
     * 
     * @param digits
     *            the number of digits the generated HOTP value should contain
     *            (must be between {@link #MIN_ALLOWED_DIGITS} and
     *            {@link #MAX_ALLOWED_DIGITS} inclusive)
     * 
     * @return this {@code HOTPBuilder} instance initialized with the specified
     *         {@code digits}.
     * 
     * @throws IllegalArgumentException
     *             if {@code digits} is not in [{@link #MIN_ALLOWED_DIGITS},
     *             {@link #MAX_ALLOWED_DIGITS}].
     */
    public HOTPBuilder digits(int digits) {
        Preconditions.checkArgument(Range.closed(MIN_ALLOWED_DIGITS, MAX_ALLOWED_DIGITS).contains(digits));
        this.digits = digits;
        return this;
    }

    /**
     * Build a HMAC-based One-time Password {@link HOTP} using the key, digits,
     * and moving factor values contained in this builder. Note that the builder
     * instance can be reused for subsequent configuration/generation calls.
     * 
     * @return a HMAC-based One-time Password {@link HOTP} instance.
     */
    public HOTP build() {
        // Put movingFactor value into text byte array.
        byte[] text = ByteBuffer.allocate(8).putLong(movingFactor).array();

        // Step 1: Generate the HMAC-SHA-1 hash.
        byte[] hash = computeHmacSha1(key, text);

        // Step 2: Dynamic Truncation as per section 5.3 of RFC 4226.
        // -
        // "... Let OffsetBits be the low-order 4 bits of String[19] (where String = String[0]...String[19]) ..."
        // -
        // "... Let P = String[OffSet]...String[OffSet+3] ... Return the Last 31 bits of P ..."
        int offset = hash[hash.length - 1] & 0xf;
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        // Step 3: Compute the HOTP value, and ensure it contains the configured
        // number of digits.
        int otp = binary % ((int) Math.pow(10, digits));
        String hotp = Strings.padStart(Integer.toString(otp), digits, '0');

        return new HOTP(hotp, digits, movingFactor);
    }

    /**
     * Returns the HMAC-SHA-1 hash with {@code keyBytes} as the key, and
     * {@code text} as the message.
     *
     * @param keyBytes
     *            the bytes to use for the HMAC key
     * @param text
     *            the message or text to be authenticated
     * 
     * @return the HMAC-SHA-1 hash with {@code keyBytes} as the key, and
     *         {@code text} as the message.
     */
    private byte[] computeHmacSha1(byte[] keyBytes, byte[] text) {
        try {
            Mac hmac = Mac.getInstance(HmacShaAlgorithm.HMAC_SHA_1.getAlgorithm());
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }

}