package com.lochbridge.oath.otp;

/**
 * An immutable representation of an HMAC-Based One-Time Password as per RFC
 * 4226.
 * <p>
 * Refer to {@link HOTPBuilder} on how to generate a {@code HOTP}.
 * </p>
 * 
 * @see <a href="https://tools.ietf.org/html/rfc4226">RFC 4226</a>
 */
public final class HOTP {

    private final String value;
    private final int digits;
    private final long movingFactor;

    /**
     * Creates a new instance of an HMAC-based one time password. Use the static
     * method to obtain a {@link HOTPBuilder} instance and obtain a {@code HOTP}
     * from that. Note that all parameters are assumed to be valid since the
     * {@link HOTPBuilder} is responsible for validation, and creation of
     * {@link HOTP}s.
     * 
     * @param value
     *            the HMAC-based one time password value
     * @param digits
     *            the number of digits the generated HOTP value contains
     * @param movingFactor
     *            the moving factor
     */
    HOTP(String value, int digits, long movingFactor) {
        this.value = value;
        this.digits = digits;
        this.movingFactor = movingFactor;
    }

    /**
     * Returns a new {@link HOTPBuilder} instance initialized with the specified
     * {@code key}.
     * 
     * @param key
     *            the shared secret key
     * 
     * @return a new {@link HOTPBuilder} instance.
     * 
     * @throws NullPointerException
     *             if {@code key} is {@code null}.
     */
    public static HOTPBuilder key(byte[] key) {
        return new HOTPBuilder(key);
    }

    /**
     * Returns the HMAC-based one time password value.
     * 
     * @return the HMAC-based one time password value.
     */
    public String value() {
        return value;
    }

    /**
     * Returns the number of digits of this {@code HOTP}.
     * 
     * @return the number of digits of this {@code HOTP}.
     */
    public int digits() {
        return digits;
    }

    /**
     * Returns the moving factor used to generate this {@code HOTP}.
     * 
     * @return the moving factor used to generate this {@code HOTP}.
     */
    public long movingFactor() {
        return movingFactor;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return value.hashCode();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        HOTP other = (HOTP) obj;
        return value.equals(other.value);
    }

}