package com.lochbridge.oath.otp.keyprovisioning.qrcode;

import static org.junit.Assert.assertEquals;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.imageio.ImageIO;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.io.BaseEncoding;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.lochbridge.oath.otp.keyprovisioning.OTPAuthURI;
import com.lochbridge.oath.otp.keyprovisioning.OTPAuthURIBuilder;
import com.lochbridge.oath.otp.keyprovisioning.OTPKey;
import com.lochbridge.oath.otp.keyprovisioning.OTPKey.OTPType;
import com.lochbridge.oath.otp.keyprovisioning.qrcode.QRCodeWriter.ErrorCorrectionLevel;

public class TestQRCodeWriter {
    
    private static Path pathOfQRCodeImage = null;
    private static OTPAuthURI TOTP_AUTH_URI = null;
    
    @BeforeClass
    public static void setUp() throws IOException {
        pathOfQRCodeImage = Files.createTempFile("qrcode", "png", new FileAttribute[] {});
        
        OTPKey key = new OTPKey(BaseEncoding.base32().encode("12345678901234567890".getBytes(StandardCharsets.US_ASCII)), OTPType.TOTP);
        String issuer = "Acme Corporation";
        String accountName = "Alice Smith";
        String label = String.format("%s:%s", issuer, accountName);
        TOTP_AUTH_URI = OTPAuthURIBuilder.key(key).issuer(issuer).digits(6).timeStep(TimeUnit.SECONDS.toMillis(30)).build(label, true);
    }
    
    @AfterClass
    public static void tearDown() {
        if (pathOfQRCodeImage != null) {
            File file = pathOfQRCodeImage.toFile();
            if (file.exists()) {
                file.delete();
            }
        }
    }
    
    private static String getQRCodeImageRawText(Path path) throws IOException, NotFoundException {
        Map<DecodeHintType, Object> hints = new Hashtable<DecodeHintType, Object>();
        hints.put(DecodeHintType.CHARACTER_SET, StandardCharsets.UTF_8.name());
        try(FileInputStream fis = new FileInputStream(path.toFile())) {
            BufferedImage bi = ImageIO.read(fis);
            BinaryBitmap binaryBitmap = new BinaryBitmap(new HybridBinarizer(new BufferedImageLuminanceSource(bi)));
            Result result = new MultiFormatReader().decode(binaryBitmap, hints);
            return result.getText();
        }
    }
    
    @Test(expected = NullPointerException.class)
    public void fromURIShouldFailWhenURIArgumentIsNull() {
        QRCodeWriter.fromURI(null);
    }
    
    @Test(expected = NullPointerException.class)
    public void writeToFileShouldFailWhenPathArgumentIsNull() throws IOException {
        QRCodeWriter.fromURI(TOTP_AUTH_URI).write((Path) null);
    }
    
    @Test(expected = NullPointerException.class)
    public void writeToOutputStreamShouldFailWhenStreamArgumentIsNull() throws IOException {
        QRCodeWriter.fromURI(TOTP_AUTH_URI).write((OutputStream) null);
    }

    @Test
    public void writeToFileShouldSucceedWhenQRCodeIsBasedOffTheURIString() throws IOException, NotFoundException {
        QRCodeWriter.fromURI(TOTP_AUTH_URI)
            .width(300)
            .height(300)
            .errorCorrectionLevel(ErrorCorrectionLevel.H)
            .margin(4)
            .imageFormatName("PNG")
            .write(pathOfQRCodeImage);
        assertEquals(TOTP_AUTH_URI.toUriString(), getQRCodeImageRawText(pathOfQRCodeImage));
    }
    
    @Test
    public void writeToFileShouldSucceedWhenQRCodeIsBasedOffThePlainTextURIString() throws IOException, NotFoundException {
        QRCodeWriter.fromURI(TOTP_AUTH_URI)
            .width(300)
            .height(300)
            .errorCorrectionLevel(ErrorCorrectionLevel.H)
            .margin(4)
            .imageFormatName("PNG")
            .usePlainTextURI(true)
            .write(pathOfQRCodeImage);
        assertEquals(TOTP_AUTH_URI.toPlainTextUriString(), getQRCodeImageRawText(pathOfQRCodeImage));
    }
    
    @Test
    public void writeToOutputStreamShouldSucceedWhenQRCodeIsBasedOffTheURIString() throws IOException, NotFoundException {
        QRCodeWriter.fromURI(TOTP_AUTH_URI)
            .width(300)
            .height(300)
            .errorCorrectionLevel(ErrorCorrectionLevel.H)
            .margin(4)
            .imageFormatName("PNG")
            .write(new FileOutputStream(pathOfQRCodeImage.toFile()));
        assertEquals(TOTP_AUTH_URI.toUriString(), getQRCodeImageRawText(pathOfQRCodeImage));
    }
    
    @Test
    public void writeToOutputStreamShouldSucceedWhenQRCodeIsBasedOffThePlainTextURIString() throws IOException, NotFoundException {
        QRCodeWriter.fromURI(TOTP_AUTH_URI)
            .width(300)
            .height(300)
            .errorCorrectionLevel(ErrorCorrectionLevel.H)
            .margin(4)
            .imageFormatName("PNG")
            .usePlainTextURI(true)
            .write(new FileOutputStream(pathOfQRCodeImage.toFile()));
        assertEquals(TOTP_AUTH_URI.toPlainTextUriString(), getQRCodeImageRawText(pathOfQRCodeImage));
    }

}
