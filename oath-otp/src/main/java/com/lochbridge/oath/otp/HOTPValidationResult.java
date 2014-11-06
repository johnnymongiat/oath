package com.lochbridge.oath.otp;

/**
 * An immutable class representing the result of an HOTP authentication pass.
 */
public class HOTPValidationResult {

    private final boolean valid;
    private final long newMovingFactor;

    /**
     * Creates a new instance of {@code HOTPValidationResult}. Note that all 
     * parameters are assumed to be valid since the {@link HOTPValidator} is 
     * responsible for validating arguments, and creation of {@link HOTPValidationResult}s.
     * 
     * @param valid
     *            {@code true} if an HOTP authentication pass has succeeded or not {@code false}
     * @param newMovingFactor
     *            the new moving factor value that should be bound to the underlying client upon
     *            successful validation. If the validation was unsuccessful, then the original 
     *            moving factor value should be used.
     */
    HOTPValidationResult(boolean valid, long newMovingFactor) {
        this.valid = valid;
        this.newMovingFactor = newMovingFactor;
    }

    /**
     * Returns {@code true} if an HOTP authentication pass has succeeded or not {@code false}.
     * 
     * @return {@code true} if an HOTP authentication pass has succeeded or not {@code false}.
     */
    public boolean isValid() {
        return valid;
    }

    /**
     * Returns the new moving factor value that should be bound to the underlying client upon
     * successful validation. If the validation was unsuccessful, then this must return the
     * original moving factor value.
     * 
     * @return the new moving factor value that should be bound to the underlying client upon
     * successful validation.
     */
    public long getNewMovingFactor() {
        return newMovingFactor;
    }

}
