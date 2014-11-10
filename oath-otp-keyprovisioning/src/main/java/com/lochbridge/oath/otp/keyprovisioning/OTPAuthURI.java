package com.lochbridge.oath.otp.keyprovisioning;

import java.util.Locale;

import com.google.common.base.Preconditions;
import com.google.common.escape.Escaper;
import com.google.common.net.PercentEscaper;
import com.google.common.net.UrlEscapers;
import com.lochbridge.oath.otp.keyprovisioning.OTPKey.OTPType;

/**
 * An immutable class representing an OTP Auth URI. Refer to {@link OTPAuthURIBuilder}'s documentation 
 * for format, and example details.
 */
public class OTPAuthURI {
    
    private static final String URI_SAFECHARS_QUERY_STRING =
            "-._~" +      // Unreserved characters (as per the PercentEscaper: the ranges 0..9, a..z and A..Z are always safe and should not be specified here)
            "!$'()*,;" +  // The "sub-delims" characters (excluding '+', '&' and '=').
            ":@" +        // The additional "pchar" characters permitted in query parameters.
            "/?";         // The additional "query" characters permitted in query parameters.
    
    private static final Escaper QUERY_STRING_ESCAPER_NO_PLUS = new PercentEscaper(URI_SAFECHARS_QUERY_STRING, false);
    
    private final OTPKey key;
    private final String issuer;
    private final String label;
    private final long counter;
    private final int digits;
    private final long timeStep;

    /**
     * Creates a new instance of an OTP Auth URI. Note that all parameters are assumed to be valid since the
     * {@link OTPAuthURIBuilder} is responsible for validation, and creation of {@link OTPAuthURI}s.
     * 
     * @param key the {@link OTPKey}.
     * @param issuer the issuer string value indicating the provider or service this account is associated with
     * @param label the label used to identify which account the underlying key is associated with
     * @param counter the initial counter value (aka the moving factor)
     * @param digits the number of digits an OTP will contain
     * @param timeStep the time step size (in seconds) used for generating TOTPs
     */
    OTPAuthURI(OTPKey key, String issuer, String label, long counter, int digits, long timeStep) {
        this.key = key;
        this.issuer = issuer;
        this.label = label;
        this.counter = counter;
        this.digits = digits;
        this.timeStep = timeStep;
    }

    /**
     * Returns the {@link OTPKey}.
     * 
     * @return the {@link OTPKey}.
     */
    public OTPKey getKey() {
        return key;
    }

    /**
     * Returns the issuer string value indicating the provider or service this account is 
     * associated with. If the issuer is absent, issuer information may be taken from the 
     * issuer prefix of the label. If both issuer parameter and issuer label prefix are present, 
     * they will be equal.
     * <p>
     * This method returns the decoded/plain-text value of the issuer. If you want to obtain a 
     * URI-encoded version, then call the {@link #getEncodedIssuer()}
     * 
     * @return the issuer string value indicating the provider or service this account is 
     * associated with.
     */
    public String getIssuer() {
        return issuer;
    }
    
    /**
     * Returns the RFC 3986 URI-encoded value of this URI's issuer component. The decoded
     * version is obtained via {@link #getIssuer()}.
     * 
     * @return the RFC 3986 URI-encoded value of this URI's issuer component.
     */
    public String getEncodedIssuer() {
        return issuer == null ? null : safeEncodeIssuer(issuer);
    }

    /**
     * Returns the label used to identify which account the underlying key is 
     * associated with. It contains an account name, optionally prefixed by an issuer 
     * string identifying the provider or service managing that account. This issuer 
     * prefix can be used to prevent collisions between different accounts with different 
     * providers that might be identified using the same account name, e.g. the user's 
     * email address.
     * <p>
     * The issuer prefix and account name are separated by a literal colon, and optional 
     * spaces may precede the account name. Neither issuer nor account name may themselves 
     * contain a colon.
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
     * <p>
     * This method returns the decoded/plain-text value of the label. If you want to obtain a 
     * URI-encoded version, then call the {@link #getEncodedLabel()}
     * 
     * @return the label used to identify which account the underlying key is associated with.
     */
    public String getLabel() {
        return label;
    }
    
    /**
     * Returns the RFC 3986 URI-encoded value of this URI's label component. The decoded
     * version is obtained via {@link #getLabel()}.
     * 
     * @return the RFC 3986 URI-encoded value of this URI's label component.
     */
    public String getEncodedLabel() {
        return safeEncodeLabel(label);
    }

    /**
     * Returns the initial counter value (aka the moving factor). This parameter is only 
     * applicable if the underlying {@code OTPKey} type is HOTP, otherwise it is ignored 
     * when constructing the corresponding URI string.
     * 
     * @return the initial counter value (aka the moving factor).
     */
    public long getCounter() {
        return counter;
    }

    /**
     * Returns the number of digits an OTP will contain.
     * 
     * @return the number of digits an OTP will contain.
     */
    public int getDigits() {
        return digits;
    }

    /**
     * Returns the time step size (in seconds) used for generating TOTPs. 
     * This parameter is only applicable if the underlying {@code OTPKey} 
     * type is TOTP, otherwise it is ignored when constructing the corresponding
     * URI string.
     * 
     * @return the time step size (in seconds) used for generating TOTPs.
     */
    public long getTimeStep() {
        return timeStep;
    }
    
    /**
     * Returns {@code true} if the URI is associated with an HOTP OTP type, {@code false} otherwise.
     * 
     * @return {@code true} if the URI is associated with an HOTP OTP type, {@code false} otherwise.
     */
    public boolean isHOTP() {
        return key.getType().equals(OTPType.HOTP);
    }
    
    /**
     * Returns {@code true} if the URI is associated with an TOTP OTP type, {@code false} otherwise.
     * 
     * @return {@code true} if the URI is associated with an TOTP OTP type, {@code false} otherwise.
     */
    public boolean isTOTP() {
        return key.getType().equals(OTPType.TOTP);
    }
    
    private String contstructUriString(boolean ignoreEncodeSettings) {
        StringBuilder sb = new StringBuilder();
        sb.append("otpauth://");
        sb.append(key.getType().getName().toLowerCase(Locale.US));
        sb.append("/");
        sb.append(ignoreEncodeSettings ? label : safeEncodeLabel(label));
        sb.append("?secret=");
        sb.append(key.getKey());
        if (issuer != null) {
            sb.append("&issuer=");
            sb.append(ignoreEncodeSettings ? issuer : safeEncodeIssuer(issuer));
        }
        sb.append("&digits=");
        sb.append(digits);
        if (isHOTP()) {
            sb.append("&counter=");
            sb.append(counter);
        }
        if (isTOTP()) {
            sb.append("&period=");
            sb.append(timeStep);
        }
        return sb.toString();
    }
    
    /**
     * Returns the content of this URI as a string, with no URI-encoding of any of the components. This assumes that the 
     * individual components were themselves un-encoded when this instance was built.
     * 
     * @return the content of this URI as a string, with no URI-encoding of any of the components.
     */
    public String toPlainTextUriString() {
        return contstructUriString(true);
    }

    /**
     * Returns the content of this URI as a string, with the label, and/or issuer components URI-encoded as per the
     * configuration at the time this URI was built. If you want to obtain an un-encoded or plain-text string version
     * then call the {@link #toPlainTextUriString()}. The latter assumes that the individual components were themselves
     * un-encoded when this instance was built. 
     * <p>
     * The URI conforms to the following format:
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
     *
     * @return the content of this URI as a string, with the label, and/or issuer components URI-encoded as per the
     * configuration at the time this URI was built.
     */
    public String toUriString() {
        return contstructUriString(false);
    }
    
    /**
     * Returns the escaped form of a given {@code label} string so that it can be
     * safely included in {@link OTPAuthURI}s. All non-ASCII characters, and 
     * the slash character ("/") are escaped.
     *
     * <p>When escaping a String, the following rules apply:
     * <ul>
     * <li>The alphanumeric characters "a" through "z", "A" through "Z" and "0"
     *     through "9" remain the same.
     * <li>The unreserved characters ".", "-", "~", and "_" remain the same.
     * <li>The general delimiters "@" and ":" remain the same.
     * <li>The sub-delimiters "!", "$", "&amp;", "'", "(", ")", "*", "+", ",", ";",
     *     and "=" remain the same.
     * <li>The space character " " is converted into %20.
     * <li>All other characters are converted into one or more bytes using UTF-8
     *     encoding and each byte is then represented by the 3-character string
     *     "%XY", where "XY" is the two-digit, uppercase, hexadecimal
     *     representation of the byte value.
     * </ul>
     *
     * <p><b>Note:</b> Escaped characters produce uppercase hexadecimal sequences. 
     * From <a href="http://www.ietf.org/rfc/rfc3986.txt">RFC 3986</a>:<br>
     * <i>"URI producers and normalizers should use uppercase hexadecimal digits
     * for all percent-encodings."</i>
     * 
     * @param label the OTP Auth URI label to be escaped
     * 
     * @return the escaped form of a given {@code label} string
     */
    public static final String encodeLabel(String label) {
        Preconditions.checkNotNull(label);
        return safeEncodeLabel(label);
    }
    
    private static final String safeEncodeLabel(String label) {
        return UrlEscapers.urlPathSegmentEscaper().escape(label);
    }
    
    /**
     * Returns the escaped form of a given {@code issuer} string so that it can be
     * safely included in {@link OTPAuthURI}s. All non-ASCII characters are escaped.
     *
     * <p>When escaping a String, the following rules apply:
     * <ul>
     * <li>The alphanumeric characters "a" through "z", "A" through "Z" and "0"
     *     through "9" remain the same.
     * <li>The unreserved characters ".", "-", "~", and "_" remain the same.
     * <li>The additional "pchar" characters "@" and ":" remain the same.
     * <li>The sub-delimiters "!", "$", "'", "(", ")", "*", ",", and ";" remain the same.
     * ('+', '&' and '=' are excluded)
     * <li>The additional "query" characters "/", and "?" remain the same.
     * <li>The space character " " is converted into %20.
     * <li>All other characters are converted into one or more bytes using UTF-8
     *     encoding and each byte is then represented by the 3-character string
     *     "%XY", where "XY" is the two-digit, uppercase, hexadecimal
     *     representation of the byte value.
     * </ul>
     *
     * <p><b>Note:</b> Escaped characters produce uppercase hexadecimal sequences. 
     * From <a href="http://www.ietf.org/rfc/rfc3986.txt">RFC 3986</a>:<br>
     * <i>"URI producers and normalizers should use uppercase hexadecimal digits
     * for all percent-encodings."</i>
     * 
     * @param issuer the OTP Auth URI issuer to be escaped
     * 
     * @return the escaped form of a given {@code issuer} string
     */
    public static final String encodeIssuer(String issuer) {
        Preconditions.checkNotNull(issuer);
        return safeEncodeIssuer(issuer);
    }
    
    public static final String safeEncodeIssuer(String issuer) {
        return QUERY_STRING_ESCAPER_NO_PLUS.escape(issuer);
    }

}
