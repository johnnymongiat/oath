package com.lochbridge.oath.otp.keyprovisioning.qrcode;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Hashtable;
import java.util.Map;

import com.google.common.base.Preconditions;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.Writer;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.lochbridge.oath.otp.keyprovisioning.OTPAuthURI;

/**
 * Class that renders an {@link OTPAuthURI} as a QR Code image.
 * <p>
 * Example:
 * <pre>
 * OTPKey key = new OTPKey("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", OTPType.TOTP);
 * String issuer = "Acme Corporation";
 * String label = issuer + ":Alice Smith";
 * 
 * // Create the OTP Auth URI. 
 * OTPAuthURI uri = OTPAuthURIBuilder.fromKey(key).label(label).issuer(issuer).digits(6).timeStep(30000L).build();
 * 
 * // Render a QR Code into a file.
 * File file = new File("path/to/qrcode.png");
 * QRCodeWriter.fromURI(uri).width(300).height(300).errorCorrectionLevel(ErrorCorrectionLevel.H).margin(4).imageFormatName("PNG").write(file.toPath());
 * </pre>
 */
public class QRCodeWriter {

    private final OTPAuthURI uri;
    private int width = 250;
    private int height = 250;
    private ErrorCorrectionLevel errorCorrectionLevel = ErrorCorrectionLevel.L;
    private int margin = 4;
    private String imageFormatName = "PNG";

    private QRCodeWriter(OTPAuthURI uri) {
        this.uri = uri;
    }

    /**
     * Returns a new {@link QRCodeWriter} instance initialized with the
     * specified {@link OTPAuthURI}.
     * 
     * @param uri
     *            the {@link OTPAuthURI}
     * 
     * @return a new {@link QRCodeWriter} instance.
     * 
     * @throws NullPointerException
     *             if {@code uri} is {@code null}.
     */
    public static QRCodeWriter fromURI(OTPAuthURI uri) {
        Preconditions.checkNotNull(uri);
        return new QRCodeWriter(uri);
    }

    /**
     * Returns this {@code QRCodeWriter} instance initialized with the
     * specified width of the QR code image. The default width is 250 pixels.
     * 
     * @param width
     *            the width of the QR code image.
     * 
     * @return this {@code QRCodeWriter} instance initialized with the
     *         specified width of the QR code image.
     */
    public QRCodeWriter width(int width) {
        this.width = width;
        return this;
    }

    /**
     * Returns this {@code QRCodeWriter} instance initialized with the
     * specified height of the QR code image. The default width is 250 pixels.
     * 
     * @param height
     *            the height of the QR code image.
     * 
     * @return this {@code QRCodeWriter} instance initialized with the
     *         specified height of the QR code image.
     */
    public QRCodeWriter height(int height) {
        this.height = height;
        return this;
    }

    /**
     * Returns this {@code QRCodeWriter} instance initialized with the
     * specified {@link ErrorCorrectionLevel}. The default is
     * {@link ErrorCorrectionLevel.L}.
     * 
     * @param errorCorrectionLevel
     *            the error correction level.
     * 
     * @return this {@code QRCodeWriter} instance initialized with the
     *         specified {@link ErrorCorrectionLevel}.
     */
    public QRCodeWriter errorCorrectionLevel(ErrorCorrectionLevel errorCorrectionLevel) {
        this.errorCorrectionLevel = errorCorrectionLevel;
        return this;
    }

    /**
     * Returns this {@code QRCodeWriter} instance initialized with the
     * specified margin. The margin is the width of the white border around the
     * data portion of the QR code. This is in rows, not in pixels. The default
     * value is 4.
     * 
     * @param margin
     *            the margin.
     * 
     * @return this {@code QRCodeWriter} instance initialized with the
     *         specified margin.
     */
    public QRCodeWriter margin(int margin) {
        this.margin = margin;
        return this;
    }

    /**
     * Returns this {@code QRCodeWriter} instance initialized with the
     * specified informal image format name to use when generating the QR code
     * image. The default is "PNG".
     * 
     * @param imageFormatName
     *            the informal image format name.
     * 
     * @return this {@code QRCodeWriter} instance initialized with the
     *         specified informal image format name to use when generating the
     *         QR code image.
     */
    public QRCodeWriter imageFormatName(String imageFormatName) {
        this.imageFormatName = imageFormatName;
        return this;
    }
    
    /**
     * Writes a QR code to a stream using this writer's configured parameters.
     * 
     * @param os {@link OutputStream} to write image to
     * 
     * @throws NullPointerException if {@code os} is {@code null}
     * @throws IOException <ul><li>if writes to the stream fail</li><li>if contents cannot be encoded legally in a format</li></ul>
     */
    public void write(OutputStream os) throws IOException {
        Preconditions.checkNotNull(os);
        doWrite(os, null);
    }

    /**
     * Writes a QR code to a file using this writer's configured parameters.
     * 
     * @param path file {@link Path} to write image to
     * 
     * @throws NullPointerException if {@code path} is {@code null}
     * @throws IOException <ul><li>if writes to the stream fail</li><li>if contents cannot be encoded legally in a format</li></ul>
     */
    public void write(Path path) throws IOException {
        Preconditions.checkNotNull(path);
        doWrite(null, path);
    }
    
    private void doWrite(OutputStream os, Path path) throws IOException {
        try {
            Writer writer = new MultiFormatWriter();
            Map<EncodeHintType, Object> hints = new Hashtable<EncodeHintType, Object>();
            hints.put(EncodeHintType.CHARACTER_SET, StandardCharsets.UTF_8.name());
            hints.put(EncodeHintType.MARGIN, Integer.valueOf(margin));
            hints.put(EncodeHintType.ERROR_CORRECTION, com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.forBits(errorCorrectionLevel.getBits()));
            BitMatrix matrix = writer.encode(uri.toUriString(), BarcodeFormat.QR_CODE, width, height, hints);
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

}
