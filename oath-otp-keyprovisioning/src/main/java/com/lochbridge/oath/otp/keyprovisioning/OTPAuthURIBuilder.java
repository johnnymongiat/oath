package com.lochbridge.oath.otp.keyprovisioning;

import java.util.concurrent.TimeUnit;

import com.google.common.base.Preconditions;
import com.google.common.collect.Range;
import com.lochbridge.oath.otp.HOTPBuilder;
import com.lochbridge.oath.otp.TOTPBuilder;
import com.lochbridge.oath.otp.keyprovisioning.OTPKey.OTPType;

/**
 * A class that creates {@link OTPAuthURI}s representing an OTP Auth URI (as per the 
 * <a href="https://code.google.com/p/google-authenticator/wiki/KeyUriFormat">Google Authenticator URI format</a>):
 * <pre>otpauth://{type}/{label}?secret={secret}&issuer={issuer}&digits={digits}&counter={counter}&period={period}</pre>
 * <ul>
 * <li>{@code type}: The OTP type, either "hotp" or "totp".</li>
 * <li>{@code label}: The label used to identify which account the underlying key is associated with. 
 * It contains an account name, which is a URI-encoded string, optionally prefixed by an issuer string 
 * identifying the provider or service managing that account.</li>
 * <li>{@code secret}: The encoded value of the underlying OTP shared secret key.</li>
 * <li>{@code issuer}: String identifying the provider or service managing that account.</li>
 * <li>{@code counter}: The initial counter value (aka the moving factor). The parameter will only be present 
 * if the {@code type} is "hotp".</li>
 * <li>{@code period}: The time step size (in seconds) used for generating TOTPs. The parameter will only be present 
 * if the {@code type} is "totp".</li>
 * </ul>
 * <p>
 * Example:
 * <pre>
 * String secretKey = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // a base32 encoded shared secret key.
 * String issuer = "Acme Corporation";
 * String label = issuer + ":Alice Smith";
 * OTPAuthURI uri = OTPAuthURIBuilder.key(new OTPKey(secretKey, OTPType.TOTP)).issuer(issuer).digits(6).timeStep(30000L).build(label, true);
 * // Prints "otpauth://totp/Acme%20Corporation:Alice%20Smith?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Acme%20Corporation&digits=6&period=30"
 * System.out.println(uri.toUriString());
 * </pre>
 */
public class OTPAuthURIBuilder {

    private final OTPKey key;
    private String issuer;
    private boolean encodeIssuer = true;
    private long counter = 0;
    private int digits;
    private long timeStep = TOTPBuilder.DEFAULT_TIME_STEP;

    private OTPAuthURIBuilder(OTPKey key) {
        this.key = key;
        this.digits = (key.getType().equals(OTPType.HOTP)) ? HOTPBuilder.DEFAULT_DIGITS : TOTPBuilder.DEFAULT_DIGITS;
    }

    /**
     * Returns a new {@link OTPAuthURIBuilder} instance initialised with the
     * specified {@link OTPKey}.
     * 
     * @param key
     *            the {@link OTPKey}
     * 
     * @return a new {@link OTPAuthURIBuilder} instance.
     * 
     * @throws NullPointerException
     *             if {@code key} is {@code null}.
     */
    public static OTPAuthURIBuilder key(OTPKey key) {
        Preconditions.checkNotNull(key);
        return new OTPAuthURIBuilder(key);
    }

    /**
     * Returns this {@code OTPAuthURIBuilder} instance initialised with the
     * specified issuer. The issuer parameter is a string value indicating the
     * provider or service this account is associated with. If the issuer 
     * parameter is absent, issuer information may be taken from the issuer prefix 
     * of the label. If both issuer parameter and issuer label prefix are present, 
     * they MUST be equal.
     * <p>
     * If you do NOT want the issuer parameter to be URL-encoded according to RFC 3986, then
     * call the {@link #omitIssuerEncoding()} on this builder instance. Likewise, if you want
     * to reset RFC 3986 URL-encoding of the issuer, then call {@link #includeIssuerEncoding()}.
     * The default configuration is to URL-encode the value.
     * <p>
     * Even though this parameter is optional, it is <b>STRONGLY
     * RECOMMEDNDED</b> that it be set along with the issuer label prefix.
     * <p>
     * Valid values corresponding to the following label prefix examples would
     * be:
     * <ul>
     * <li>if label is {@code "Example:alice@gmail.com"}, then issuer is
     * {@code "Example"}</li>
     * <li>if label is {@code "Provider1:Alice%20Smith"}, then issuer is
     * {@code "Provider1"}</li>
     * <li>if label is {@code "Big%20Corporation%3A%20alice@bigco.com"}, then
     * issuer is {@code "Big%20Corporation"} (URL-encoded according to RFC 3986)</li>
     * </ul>
     * <p>
     * <b>Side note:</b> Older Google Authenticator implementations ignore the issuer parameter
     * and rely upon the issuer label prefix to disambiguate accounts. Newer
     * implementations will use the issuer parameter for internal
     * disambiguation, it will not be displayed to the user. We recommend using
     * both issuer label prefix and issuer parameter together to safely support
     * both old and new Google Authenticator versions.
     * 
     * @param issuer
     *            the issuer (un-encoded/plain-text). Use the {@link #omitIssuerEncoding()} or
     *            {@link #includeIssuerEncoding()} to disable or enable RFC 3986 URL-encoding
     *            of the value (the default configuration is to URL-encode the value).
     * 
     * @return this {@code OTPAuthURIBuilder} instance initialised with the
     *         specified issuer.
     * 
     * @throws IllegalArgumentException
     *             if {@code issuer} is not {@code null}, and contains a literal or 
     *             URL-encoded colon.
     */
    public OTPAuthURIBuilder issuer(String issuer) {
        if (issuer != null) {
            // Ensure the issuer does contain a colon.
            Preconditions.checkArgument(!(issuer.contains(":") || issuer.contains("%3A")), 
                    "The issuer cannot contain a colon!");
        }
        this.issuer = issuer;
        return this;
    }
    
    /**
     * Returns this {@code OTPAuthURIBuilder} instance with RFC 3986 URL-encoding
     * of the configured issuer parameter omitted.
     * <p>
     * If you want the issuer parameter to be RFC 3986 URL-encoded, then
     * call the {@link #includeIssuerEncoding()} on this builder instance.
     * 
     * @return this {@code OTPAuthURIBuilder} instance with RFC 3986 URL-encoding
     * of the configured issuer parameter omitted.
     */
    public OTPAuthURIBuilder omitIssuerEncoding() {
        encodeIssuer = false;
        return this;
    }
    
    /**
     * Returns this {@code OTPAuthURIBuilder} instance enabled with RFC 3986 URL-encoding
     * of the configured issuer parameter (if present).
     * <p>
     * If you do NOT want the issuer parameter to be RFC 3986 URL-encoded, then
     * call the {@link #omitIssuerEncoding()} on this builder instance.
     * 
     * @return this {@code OTPAuthURIBuilder} instance enabled with RFC 3986 URL-encoding
     * of the configured issuer parameter (if present).
     */
    public OTPAuthURIBuilder includeIssuerEncoding() {
        encodeIssuer = true;
        return this;
    }
    
    /**
     * Returns this {@code OTPAuthURIBuilder} instance initialised with the
     * specified digits. This parameter specifies the number of digits an 
     * OTP will contain. The default value is {@link HOTPBuilder#DEFAULT_DIGITS}
     * if the underlying {@code OTPKey} type is HOTP, otherwise {@link TOTPBuilder#DEFAULT_DIGITS}.
     * 
     * @param digits
     *            the number of digits an OTP will contain.
     * 
     * @return this {@code OTPAuthURIBuilder} instance initialised with the
     *         specified counter.
     * 
     * @throws IllegalArgumentException
     *             if {@code digits} is not in [{@link HOTPBuilder#MIN_ALLOWED_DIGITS},
     *             {@link HOTPBuilder#MAX_ALLOWED_DIGITS}] and the underlying {@code OTPKey}
     *             type is HOTP. if {@code digits} is not in [{@link TOTPBuilder#MIN_ALLOWED_DIGITS},
     *             {@link TOTPBuilder#MAX_ALLOWED_DIGITS}] and the underlying {@code OTPKey}
     *             type is TOTP.
     */
    public OTPAuthURIBuilder digits(int digits) {
        if (key.getType().equals(OTPType.HOTP)) {
            Preconditions.checkArgument(Range.closed(HOTPBuilder.MIN_ALLOWED_DIGITS, HOTPBuilder.MAX_ALLOWED_DIGITS).contains(digits));
        }
        else {
            Preconditions.checkArgument(Range.closed(TOTPBuilder.MIN_ALLOWED_DIGITS, TOTPBuilder.MAX_ALLOWED_DIGITS).contains(digits));
        }
        this.digits = digits;
        return this;
    }

    /**
     * Returns this {@code OTPAuthURIBuilder} instance initialised with the
     * specified initial counter value (aka the moving factor). The parameter
     * is required if the underlying {@code OTPKey} type is HOTP, otherwise 
     * it is ignored. The default value is 0.
     * 
     * @param counter
     *            the initial counter value.
     * 
     * @return this {@code OTPAuthURIBuilder} instance initialised with the
     *         specified counter.
     *         
     * @throws IllegalArgumentException
     *             if {@code counter} is < 0.
     */
    public OTPAuthURIBuilder counter(long counter) {
        Preconditions.checkArgument(counter >= 0);
        this.counter = counter;
        return this;
    }
    
    /**
     * Returns this {@code OTPAuthURIBuilder} instance initialised with the
     * specified timeStep. This parameter specifies the time step size (in 
     * milliseconds) used for generating TOTPs. The parameter is required if the 
     * underlying {@code OTPKey} type is TOTP, otherwise it is ignored. 
     * The default value is {@link TOTPBuilder#DEFAULT_TIME_STEP}.
     * 
     * @param timeStep
     *            the time step size (in milliseconds) used for generating TOTPs.
     * 
     * @return this {@code OTPAuthURIBuilder} instance initialised with the
     *         specified timeStep.
     * 
     * @throws IllegalArgumentException
     *             if {@code timeStep} is <= 0.
     */
    public OTPAuthURIBuilder timeStep(long timeStep) {
        Preconditions.checkArgument(timeStep > 0);
        this.timeStep = timeStep;
        return this;
    }
    
    /**
     * Creates an {@link OTPAuthURI} using this builder's configured parameters.
     * <p>
     * The {@code label} is used to identify which account the underlying key is 
     * associated with. It contains an account name, optionally prefixed by an issuer 
     * string identifying the provider or service managing that account. This issuer 
     * prefix can be used to prevent collisions between different accounts with different 
     * providers that might be identified using the same account name, e.g. the user's 
     * email address.
     * <p>
     * The issuer prefix and account name should be separated by a literal colon, and optional 
     * spaces may precede the account name. Neither issuer nor account name may themselves 
     * contain a colon.
     * <p>
     * Set the {@code encodeLabel} argument to {@code true} if you want the {@code label} to be
     * URI-encoded, or {@code false} to ignore encoding.
     * <p>
     * Some examples:
     * <ul>
     * <li>{@code "Example:alice@gmail.com"}, where {@code "Example"} is the issuer prefix, and
     * {@code "alice@gmail.com"} is the account name</li>
     * <li>{@code "Provider1:Alice%20Smith"}, where {@code "Provider1"} is the issuer prefix, and
     * {@code "Alice%20Smith"} is the account name (URI-encoded)</li>
     * <li>{@code "Big%20Corporation:%20alice@bigco.com"}, where {@code "Big%20Corporation"} is
     * the issuer prefix, and {@code "%20alice@bigco.com"} is the account name (URI-encoded)</li>
     * </ul>
     * 
     * @param label the label (un-encoded/plain-text) used to identify which account the underlying key is associated with.
     * @param encodeLabel whether the {@code label} should be URI-encoded ({@code true}) or not ({@code false}).
     * 
     * @throws NullPointerException
     *             if {@code label} {@code null}.
     * @throws IllegalArgumentException
     *             <ul>
     *             <li>if the {@code label}'s account name portion is missing/empty.</li>
     *             <li>if the {@code label}'s account name portion contains a colon character.</li>
     *             <li>if {@code issuer} is not {@code null}, and does not match the {@code label}'s issuer prefix (if present).</li>
     *             </ul>
     * 
     * @return an {@link OTPAuthURI} using this builder's configured parameters.
     */
    public OTPAuthURI build(String label, boolean encodeLabel) {
        Preconditions.checkNotNull(label);
        
        int index = label.indexOf(":");
        String labelIssuerPrefix = (index > 0) ? label.substring(0, index) : null;
        if (labelIssuerPrefix == null) {
            // Then the label itself represents the account name.
            Preconditions.checkArgument(!label.trim().isEmpty(), "The label's account name is missing or empty!");
            Preconditions.checkArgument(!label.contains(":"), "The 'label' cannot contain any ':' characters other than the separator between the issuer prefix and account name!");
        }
        else {
            if (label.length() <= index) {
                throw new IllegalArgumentException("The label's account name is missing!");
            }
            String accountName = label.substring(index + 1);
            Preconditions.checkArgument(!accountName.trim().isEmpty(), "The label's account name is empty!");
            Preconditions.checkArgument(!accountName.contains(":"), "The label's account name cannot contain any ':' characters!");
            // Verify that the label's issuer prefix is the same as the configured issuer parameter (if itself present).
            if (issuer != null) {
                Preconditions.checkArgument(issuer.equals(labelIssuerPrefix), "The 'issuer' and label issuer prefix values are different!");
            }
        }
        
        return new OTPAuthURI(key, issuer, encodeIssuer, label, encodeLabel, counter, digits, TimeUnit.MILLISECONDS.toSeconds(timeStep));
    }

}
