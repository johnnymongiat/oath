package com.lochbridge.oath.otp;

import com.google.common.base.Preconditions;

/**
 * A HMAC-based One-time Password (HOTP) validator.
 * 
 * <p>
 * As per <a href="https://tools.ietf.org/html/rfc4226#section-7.2">RFC 4226 (section 7.2)</a>:
 * <p>
 * "The HOTP client (hardware or software token) increments its counter 
 * and then calculates the next HOTP value.  If the value received by the 
 * authentication server matches the value calculated by the client, then 
 * the HOTP value is validated.  In this case, the server increments the 
 * counter value by one.
 * <p>
 * If the value received by the server does not match the value
 * calculated by the client, the server initiates the resynch protocol 
 * (look-ahead window) before it requests another pass.
 * <p>
 * If the resynch fails, the server asks then for another authentication 
 * pass of the protocol to take place, until the maximum number of authorized 
 * attempts is reached.
 * <p>
 * If and when the maximum number of authorized attempts is reached, the
   server SHOULD lock out the account and initiate a procedure to inform
   the user."
 * <p>
 * Example:
 * </p>
 * 
 * <pre>
 * // Assume the current moving factor of a given client's HOTP is 5, and HOTP's are 6-digits.
 * String clientHOTPValue = "..."; // The client's HOTP value as received by the authentication server.
 * byte[] key = ...; // The client's shared secret key.
 * long currentMovingFactor = 5; // The client's current moving factor as determined by the authentication server.
 * 
 * // Configure a validator to look-ahead an additional 2 times.
 * HOTPValidationResult result = HOTPValidator.lookAheadWindow(2).validate(key, currentMovingFactor, 6, clientHOTPValue);
 * if (result.isValid()) {
 *     // Validation has succeeded, so the authentication server would need to update the client's current moving factor
 *     // mapping so that subsequent validation requests reference this new/updated value. the new/updated value is
 *     // captured in the returned HOTPValidationResult via the getNewMovingFactor() method.
 *     updateMovingFactorForClient(...., result.getNewMovingFactor());
 *     return;
 * }
 * // Validation failed, so the authentication server should ask for another authentication pass of the HOTP validation
 * // protocol, until the maximum number of authorized attempts (throttling parameter) is reached. Once the maximum number 
 * // of authorized attempts has been reached, the authentication server should lock out the client's account, and initiate
 * // a procedure to inform the user.
 * throw new Exception("HOTP validation attempt failed");
 * </pre>
 * 
 * @author Johnny Mongiat
 *
 * @see <a href="https://tools.ietf.org/html/rfc4226#section-7.2">RFC 4226 (section 7.2)</a>
 */
public final class HOTPValidator {

    /** The default look ahead window verification size. */
    public static final int DEFAULT_LOOK_AHEAD_WINDOW = 2;

    private final int lookAheadWindow;

    /**
     * Creates a new instance of {@code TOTPValidator} initialized with the
     * specified {@code window} verification size.
     * 
     * @param lookAheadWindow
     *            the look ahead window verification size
     * 
     * @throws IllegalArgumentException
     *             if {@code lookAheadWindow} is < 1.
     */
    private HOTPValidator(int lookAheadWindow) {
        Preconditions.checkArgument(lookAheadWindow >= 1);
        this.lookAheadWindow = lookAheadWindow;
    }

    /**
     * Returns a new {@link HOTPValidator} instance initialized with the
     * {@link #DEFAULT_LOOK_AHEAD_WINDOW} verification size.
     * 
     * @return a new {@link HOTPValidator} instance.
     */
    public static HOTPValidator defaultLookAheadWindow() {
        return lookAheadWindow(DEFAULT_LOOK_AHEAD_WINDOW);
    }

    /**
     * Returns a new {@link HOTPValidator} instance initialized with the
     * specified {@code lookAheadWindow} verification size.
     * 
     * @param lookAheadWindow
     *            the look ahead window verification size
     * 
     * @return a new {@link HOTPValidator} instance.
     * 
     * @throws IllegalArgumentException
     *             if {@code lookAheadWindow} is {@literal <} 1.
     */
    public static HOTPValidator lookAheadWindow(int lookAheadWindow) {
        return new HOTPValidator(lookAheadWindow);
    }

    /**
     * Returns an {@link HOTPValidationResult} detailing a successful HOTP validation or not.
     * 
     * @param key
     *            the shared secret key
     * @param movingFactor
     *            the current moving factor
     * @param digits
     *            the number of digits an HOTP should contain
     * @param value
     *            the HOTP value to validate
     * 
     * @return an {@link HOTPValidationResult} detailing a successful HOTP validation or not.
     */
    public HOTPValidationResult validate(byte[] key, long movingFactor, int digits, String value) {
        HOTPBuilder builder = HOTP.key(key).digits(digits);
        for (int i = 0; i <= lookAheadWindow; i++) {
            HOTP vhotp = builder.movingFactor(movingFactor + i).build();
            if (vhotp.value().equals(value)) {
                return new HOTPValidationResult(true, vhotp.movingFactor() + 1);
            }
        }
        return new HOTPValidationResult(false, movingFactor);
    }

}