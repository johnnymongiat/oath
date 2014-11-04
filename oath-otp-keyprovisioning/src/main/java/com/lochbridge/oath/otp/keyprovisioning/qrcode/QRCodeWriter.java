package com.lochbridge.oath.otp.keyprovisioning.qrcode;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Hashtable;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import javax.imageio.ImageIO;

import com.google.common.base.Preconditions;
import com.google.common.collect.Maps;
import com.google.common.collect.Range;
import com.google.common.net.UrlEscapers;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.Result;
import com.google.zxing.Writer;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.HybridBinarizer;
import com.lochbridge.oath.otp.HOTPBuilder;
import com.lochbridge.oath.otp.TOTPBuilder;
import com.lochbridge.oath.otp.keyprovisioning.OTPKey;
import com.lochbridge.oath.otp.keyprovisioning.OTPKey.OTPType;

/**
 * TODO javadoc
 * Class that renders an OTP key as a QR Code: otpauth://TYPE/LABEL?PARAMETERS
 * <p>
 * This is just friendly wrapper around the zxing writer.
 */
public class QRCodeWriter {

    private final OTPKey key;
    private String issuer;
    private long counter = 0;
    private int digits;
    private long timeStep = TOTPBuilder.DEFAULT_TIME_STEP;
    private int width = 250;
    private int height = 250;
    private ErrorCorrectionLevel errorCorrectionLevel = ErrorCorrectionLevel.L;
    private int margin = 4;
    private String imageFormatName = "PNG";

    private QRCodeWriter(OTPKey key) {
        this.key = key;
        this.digits = (key.getType().equals(OTPType.HOTP)) ? HOTPBuilder.DEFAULT_DIGITS : TOTPBuilder.DEFAULT_DIGITS;
    }

    /**
     * Returns a new {@link QRCodeWriter} instance initialised with the
     * specified {@link OTPKey}.
     * 
     * @param key
     *            the {@link OTPKey}
     * 
     * @return a new {@link QRCodeWriter} instance.
     * 
     * @throws NullPointerException
     *             if {@code key} is {@code null}.
     */
    public static QRCodeWriter key(OTPKey key) {
        Preconditions.checkNotNull(key);
        return new QRCodeWriter(key);
    }

    /**
     * Returns this {@code QRCodeWriter} instance initialised with the
     * specified issuer. The issuer parameter is a String value indicating the
     * provider or service this account is associated with, URL-encoded
     * according to RFC 3986. If the issuer parameter is absent, issuer
     * information may be taken from the issuer prefix of the label. If both
     * issuer parameter and issuer label prefix are present, they MUST be
     * equal.
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
     * issuer is {@code "Big%20Corporation"}</li>
     * </ul>
     * <p>
     * Older Google Authenticator implementations ignore the issuer parameter
     * and rely upon the issuer label prefix to disambiguate accounts. Newer
     * implementations will use the issuer parameter for internal
     * disambiguation, it will not be displayed to the user. We recommend using
     * both issuer label prefix and issuer parameter together to safely support
     * both old and new Google Authenticator versions.
     * 
     * @param issuer
     *            the issuer (URL-encoded according to RFC 3986).
     * 
     * @return this {@code QRCodeWriter} instance initialised with the
     *         specified issuer.
     * 
     * @throws IllegalArgumentException
     *             if {@code issuer} is not {@code null}, and contains a literal or 
     *             URL-encoded colon.
     */
    public QRCodeWriter issuer(String issuer) {
        if (issuer != null) {
            // Ensure the issuer does contain a colon.
            Preconditions.checkArgument(!(issuer.contains(":") || issuer.contains("%3A")), 
                    "The issuer cannot contain a colon!");
        }
        this.issuer = issuer;
        return this;
    }
    
    /**
     * Returns this {@code QRCodeWriter} instance initialised with the
     * specified digits. This parameter specifies the number of digits an 
     * OTP will contain. The default value is {@link HOTPBuilder#DEFAULT_DIGITS}
     * if the underlying {@code OTPKey} type is HOTP, otherwise {@link TOTPBuilder#DEFAULT_DIGITS}.
     * 
     * @param digits
     *            the number of digits an OTP will contain.
     * 
     * @return this {@code QRCodeWriter} instance initialised with the
     *         specified counter.
     * 
     * @throws IllegalArgumentException
     *             if {@code digits} is not in [{@link HOTPBuilder#MIN_ALLOWED_DIGITS},
     *             {@link HOTPBuilder#MAX_ALLOWED_DIGITS}] and the underlying {@code OTPKey}
     *             type is HOTP. if {@code digits} is not in [{@link TOTPBuilder#MIN_ALLOWED_DIGITS},
     *             {@link TOTPBuilder#MAX_ALLOWED_DIGITS}] and the underlying {@code OTPKey}
     *             type is TOTP.
     */
    public QRCodeWriter digits(int digits) {
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
     * Returns this {@code QRCodeWriter} instance initialised with the
     * specified initial counter value (aka the moving factor). The parameter
     * is required if the underlying {@code OTPKey} type is HOTP, otherwise 
     * it is ignored. The default value is 0.
     * 
     * @param counter
     *            the initial counter value.
     * 
     * @return this {@code QRCodeWriter} instance initialised with the
     *         specified counter.
     *         
     * @throws IllegalArgumentException
     *             if {@code counter} is < 0.
     */
    public QRCodeWriter counter(long counter) {
        Preconditions.checkArgument(counter >= 0);
        this.counter = counter;
        return this;
    }
    
    /**
     * Returns this {@code QRCodeWriter} instance initialised with the
     * specified timeStep. This parameter specifies the time step size (in 
     * milliseconds) used for generating TOTPs. The parameter is required if the 
     * underlying {@code OTPKey} type is TOTP, otherwise it is ignored. 
     * The default value is {@link TOTPBuilder#DEFAULT_TIME_STEP}.
     * 
     * @param timeStep
     *            the time step size (in milliseconds) used for generating TOTPs.
     * 
     * @return this {@code QRCodeWriter} instance initialised with the
     *         specified timeStep.
     * 
     * @throws IllegalArgumentException
     *             if {@code timeStep} is <= 0.
     */
    public QRCodeWriter timeStep(long timeStep) {
        Preconditions.checkArgument(timeStep > 0);
        this.timeStep = timeStep;
        return this;
    }

    /**
     * Returns this {@code QRCodeWriter} instance initialised with the
     * specified width of the QR code image. The default width is 250 pixels.
     * 
     * @param width
     *            the width of the QR code image.
     * 
     * @return this {@code QRCodeWriter} instance initialised with the
     *         specified width of the QR code image.
     */
    public QRCodeWriter width(int width) {
        this.width = width;
        return this;
    }

    /**
     * Returns this {@code QRCodeWriter} instance initialised with the
     * specified height of the QR code image. The default width is 250 pixels.
     * 
     * @param height
     *            the height of the QR code image.
     * 
     * @return this {@code QRCodeWriter} instance initialised with the
     *         specified height of the QR code image.
     */
    public QRCodeWriter height(int height) {
        this.height = height;
        return this;
    }

    /**
     * Returns this {@code QRCodeWriter} instance initialised with the
     * specified {@link ErrorCorrectionLevel}. The default is
     * {@link ErrorCorrectionLevel.L}.
     * 
     * @param errorCorrectionLevel
     *            the error correction level.
     * 
     * @return this {@code QRCodeWriter} instance initialised with the
     *         specified {@link ErrorCorrectionLevel}.
     */
    public QRCodeWriter errorCorrectionLevel(ErrorCorrectionLevel errorCorrectionLevel) {
        this.errorCorrectionLevel = errorCorrectionLevel;
        return this;
    }

    /**
     * Returns this {@code QRCodeWriter} instance initialised with the
     * specified margin. The margin is the width of the white border around the
     * data portion of the QR code. This is in rows, not in pixels. The default
     * value is 4.
     * 
     * @param margin
     *            the margin.
     * 
     * @return this {@code QRCodeWriter} instance initialised with the
     *         specified margin.
     */
    public QRCodeWriter margin(int margin) {
        this.margin = margin;
        return this;
    }

    /**
     * Returns this {@code QRCodeWriter} instance initialised with the
     * specified informal image format name to use when generating the QR code
     * image. The default is "PNG".
     * 
     * @param imageFormatName
     *            the informal image format name.
     * 
     * @return this {@code QRCodeWriter} instance initialised with the
     *         specified informal image format name to use when generating the
     *         QR code image.
     */
    public QRCodeWriter imageFormatName(String imageFormatName) {
        this.imageFormatName = imageFormatName;
        return this;
    }
    
    /**
     * Writes a QR code to a stream using this writer's configured parameters.
     * <p>
     * The {@code label} is used to identify which account the underlying key is 
     * associated with. It contains an account name, which is a URI-encoded string, 
     * optionally prefixed by an issuer string identifying the provider or service 
     * managing that account. This issuer prefix can be used to prevent collisions 
     * between different accounts with different providers that might be identified 
     * using the same account name, e.g. the user's email address.
     * <p>
     * The issuer prefix and account name should be separated by a literal or URL-encoded 
     * colon, and optional spaces may precede the account name. Neither issuer nor account 
     * name may themselves contain a colon.
     * <p>
     * Some examples:
     * <ul>
     * <li>{@code "Example:alice@gmail.com"}, where {@code "Example"} is the issuer prefix, and
     * {@code "alice@gmail.com"} is the account name</li>
     * <li>{@code "Provider1:Alice%20Smith"}, where {@code "Provider1"} is the issuer prefix, and
     * {@code "Alice%20Smith"} is the account name</li>
     * <li>{@code "Big%20Corporation%3A%20alice@bigco.com"}, where {@code "Big%20Corporation"} is
     * the issuer prefix, and {@code "%20alice@bigco.com"} is the account name</li>
     * </ul>
     * 
     * @param label the label used to identify which account the underlying key is associated with
     * @param os {@link OutputStream} to write image to
     * 
     * @throws IOException
     */
    public void write(String label, OutputStream os) throws IOException {
        checkLabel(label);
        Preconditions.checkNotNull(os);
        doWrite(label, os, null);
    }

    /**
     * Writes a QR code to a file using this writer's configured parameters.
     * <p>
     * The {@code label} is used to identify which account the underlying key is 
     * associated with. It contains an account name, which is a URI-encoded string, 
     * optionally prefixed by an issuer string identifying the provider or service 
     * managing that account. This issuer prefix can be used to prevent collisions 
     * between different accounts with different providers that might be identified 
     * using the same account name, e.g. the user's email address.
     * <p>
     * The issuer prefix and account name should be separated by a literal or URL-encoded 
     * colon, and optional spaces may precede the account name. Neither issuer nor account 
     * name may themselves contain a colon.
     * <p>
     * Some examples:
     * <ul>
     * <li>{@code "Example:alice@gmail.com"}, where {@code "Example"} is the issuer prefix, and
     * {@code "alice@gmail.com"} is the account name</li>
     * <li>{@code "Provider1:Alice%20Smith"}, where {@code "Provider1"} is the issuer prefix, and
     * {@code "Alice%20Smith"} is the account name</li>
     * <li>{@code "Big%20Corporation%3A%20alice@bigco.com"}, where {@code "Big%20Corporation"} is
     * the issuer prefix, and {@code "%20alice@bigco.com"} is the account name</li>
     * </ul>
     * 
     * @param label the label used to identify which account the underlying key is associated with
     * @param path file {@link Path} to write image to
     * 
     * @throws IOException
     */
    public void write(String label, Path path) throws IOException {
        checkLabel(label);
        Preconditions.checkNotNull(path);
        doWrite(label, null, path);
    }
    
    private void checkLabel(String label) {
        Preconditions.checkNotNull(label);
        Preconditions.checkArgument(!label.trim().isEmpty(), "The label cannot be empty!");
    }
    
    private void doWrite(String label, OutputStream os, Path path) throws IOException {
        // Verify that the label's issuer prefix (if present) is the same as the configured issuer parameter (if itself present).
        if (issuer != null) {
            int index = label.indexOf(":");
            index = (index == -1) ? label.indexOf("%3A") : index;
            String labelIssuerPrefix = (index > 0) ? label.substring(0, index) : null;
            if (labelIssuerPrefix != null) {
                // It is safe to use URLDecoder since the 'issuer' parameter is a query parameter.
                Preconditions.checkState(URLDecoder.decode(issuer, StandardCharsets.UTF_8.name()).equals(labelIssuerPrefix), 
                        "The 'issuer' and label issuer prefix values are different!");
            }
        }
        
        // Setup any additional parameters that need to part of the otpauth URI.
        Map<String, Object> parameters = createParametersMap();
        
        // Build the "otpauth://TYPE/LABEL?PARAMETERS" URI.
        String uri = createOTPAuthURI(label, key.getType().getName(), key.getKey(), parameters);
        System.out.println(uri);//TODO
        
        try {
            BitMatrix matrix = encode(uri);
            if (os != null) {
                MatrixToImageWriter.writeToStream(matrix, imageFormatName, os);
            }
            else {
                MatrixToImageWriter.writeToPath(matrix, imageFormatName, path);
            }
        } catch (WriterException e) {
            throw new IOException(e);
        }
    }
    
    private Map<String, Object> createParametersMap() {
        Map<String, Object> parameters = Maps.newLinkedHashMap();
        if (issuer != null) {
            parameters.put("issuer", issuer);
        }
        parameters.put("digits", digits);
        if (key.getType().equals(OTPType.HOTP)) {
            parameters.put("counter", counter);
        }
        if (key.getType().equals(OTPType.TOTP)) {
            parameters.put("period", TimeUnit.MILLISECONDS.toSeconds(timeStep));
        }
        return parameters;
    }
    
    private String createOTPAuthURI(String label, String otpType, String secret, Map<String, Object> parameters) {
        StringBuilder sb = new StringBuilder();
        sb.append("otpauth://");
        sb.append(otpType);
        sb.append("/");
        sb.append(label);
        sb.append("?secret=");
        sb.append(secret);
        for (Entry<String, Object> parameter : parameters.entrySet()) {
            sb.append("&");
            sb.append(parameter.getKey());
            sb.append("=");
            sb.append(parameter.getValue());
        }
        return sb.toString();
    }
    
    private BitMatrix encode(String uri) throws WriterException {
        Writer writer = new MultiFormatWriter();
        Map<EncodeHintType, Object> hints = new Hashtable<EncodeHintType, Object>();
        hints.put(EncodeHintType.CHARACTER_SET, StandardCharsets.UTF_8.name()); //TODO should this be configurable?
        hints.put(EncodeHintType.MARGIN, Integer.valueOf(margin));
        hints.put(EncodeHintType.ERROR_CORRECTION, com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.forBits(errorCorrectionLevel.getBits()));
        return writer.encode(uri, BarcodeFormat.QR_CODE, width, height, hints);
    }

    /**
     * Error Correction Level
     * <p>
     * QR codes support four levels of error correction to enable recovery of
     * missing, misread, or obscured data. Greater redundancy is achieved at the
     * cost of being able to store less data.
     * <p>
     * See ISO 18004:2006, 6.5.1.
     */
    public enum ErrorCorrectionLevel {

        /** Allows recovery of up to 7% data loss */
        L(com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.L.getBits()),
        /** Allows recovery of up to 15% data loss */
        M(com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.M.getBits()),
        /** Allows recovery of up to 25% data loss */
        Q(com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.Q.getBits()),
        /** Allows recovery of up to 30% data loss */
        H(com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.H.getBits());

        private final int bits;

        private ErrorCorrectionLevel(int bits) {
            this.bits = bits;
        }

        private int getBits() {
            return bits;
        }

    }

    //TODO remove (provide unit tests instead)
    public static void main(String[] args) throws Exception {
        final OTPKey key = new OTPKey("LHQOXRC5AAGKJZXL", OTPType.TOTP);
        final String issuer = "cfna&+@REALM.COM";
        final String encodedIssuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8.name());
        final String label = issuer.concat(": alice@google.com");
        final String encodedLabel = UrlEscapers.urlPathSegmentEscaper().escape(label);
        final int digits = 6;
        final long timeStep = TimeUnit.SECONDS.toMillis(30L);
        final int width = 250;
        final int height = 250;
        
        System.out.printf("issuer = %s%n", issuer);
        System.out.printf("encodedIssuer = %s%n", encodedIssuer);
        System.out.printf("decodedIssuer = %s%n", URLDecoder.decode(encodedIssuer, StandardCharsets.UTF_8.name()));
        System.out.printf("encodedLabel = %s%n", encodedLabel);
        System.out.printf("encodedLabel = %s%n", URLEncoder.encode(label, StandardCharsets.UTF_8.name()));
        //otpauth://totp/cfna:alice@google.com?secret=LHQOXRC5AAGKJZXL&issuer=cfna&digits=6&period=30
        //otpauth%3A//totp/cfna%3Aalice%40google.com%3Fsecret%3DLHQOXRC5AAGKJZXL%26issuer%3Dcfna%26digits%3D6%26period%3D30
        
        java.io.File file = new java.io.File("C:\\dev\\lochbridge\\oath\\oath-qrcode\\qrcode.png");
        QRCodeWriter.key(key)
            .issuer(encodedIssuer)
            .digits(digits)
            .timeStep(timeStep)
            .width(width)
            .height(height)
            .errorCorrectionLevel(ErrorCorrectionLevel.H)
            .margin(0)
            .imageFormatName("PNG")
            .write(encodedLabel, file.toPath());
        
        //=====================================
        Map<DecodeHintType, Object> hints = new Hashtable<DecodeHintType, Object>();
        hints.put(DecodeHintType.CHARACTER_SET, StandardCharsets.UTF_8.name());
        //hints.put(EncodeHintType.MARGIN, Integer.valueOf(0));
        //hints.put(EncodeHintType.ERROR_CORRECTION, com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.forBits(ErrorCorrectionLevel.H.getBits()));
        BinaryBitmap binaryBitmap = new BinaryBitmap(new HybridBinarizer(
                new BufferedImageLuminanceSource(
                    ImageIO.read(new FileInputStream(file)))));
            Result qrCodeResult = new MultiFormatReader().decode(binaryBitmap, hints);
            System.out.println(qrCodeResult.getText());
    }

}
