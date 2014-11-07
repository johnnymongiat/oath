package com.lochbridge.oath.otp.keyprovisioning;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.lochbridge.oath.otp.keyprovisioning.OTPKey.OTPType;

public class TestOTPAuthURI {
    
    private static final OTPAuthURI totpURI = new OTPAuthURI(new OTPKey("123", OTPType.TOTP), "Acme Corporation", true, "Acme Corporation:Alice Smith", true, 0, 6, 30);
    private static final OTPAuthURI hotpURI = new OTPAuthURI(new OTPKey("123", OTPType.HOTP), totpURI.getIssuer(), 
            true, totpURI.getLabel(), true, totpURI.getCounter(), totpURI.getDigits(), totpURI.getTimeStep());

    @Test
    public void encodingOfIssuerAndLabelShouldSucceed() {
        assertEquals("Acme%20Corporation", totpURI.getEncodedIssuer());
        assertEquals("Acme%20Corporation:Alice%20Smith", totpURI.getEncodedLabel());
    }
    
    @Test
    public void isHOTPAndIsTOTPShouldSucceed() {
        assertTrue(totpURI.isTOTP());
        assertFalse(totpURI.isHOTP());
        assertFalse(hotpURI.isTOTP());
        assertTrue(hotpURI.isHOTP());
    }

    @Test
    public void toPlainTextUriStringShouldSucceed() {
        assertEquals("otpauth://totp/Acme Corporation:Alice Smith?secret=123&issuer=Acme Corporation&digits=6&period=30", 
                totpURI.toPlainTextUriString());
        assertEquals("otpauth://totp/Alice Smith?secret=123&digits=6&period=30", new OTPAuthURI(totpURI.getKey(), null, true, 
                "Alice Smith", true, totpURI.getCounter(), totpURI.getDigits(), totpURI.getTimeStep()).toPlainTextUriString());
        assertEquals("otpauth://hotp/Acme Corporation:Alice Smith?secret=123&issuer=Acme Corporation&digits=6&counter=0", 
                hotpURI.toPlainTextUriString());
        assertEquals("otpauth://hotp/Alice Smith?secret=123&digits=6&counter=0", new OTPAuthURI(new OTPKey("123", OTPType.HOTP), null, true, 
                "Alice Smith", true, totpURI.getCounter(), totpURI.getDigits(), totpURI.getTimeStep()).toPlainTextUriString());
    }

    @Test
    public void toUriStringShouldSucceed() {
        assertEquals("otpauth://totp/Acme%20Corporation:Alice%20Smith?secret=123&issuer=Acme%20Corporation&digits=6&period=30", 
                totpURI.toUriString());
        assertEquals("otpauth://totp/Alice%20Smith?secret=123&digits=6&period=30", new OTPAuthURI(totpURI.getKey(), null, true, 
                "Alice Smith", true, totpURI.getCounter(), totpURI.getDigits(), totpURI.getTimeStep()).toUriString());
        assertEquals("otpauth://hotp/Acme%20Corporation:Alice%20Smith?secret=123&issuer=Acme%20Corporation&digits=6&counter=0", 
                hotpURI.toUriString());
        assertEquals("otpauth://hotp/Alice%20Smith?secret=123&digits=6&counter=0", new OTPAuthURI(new OTPKey("123", OTPType.HOTP), null, true, 
                "Alice Smith", true, totpURI.getCounter(), totpURI.getDigits(), totpURI.getTimeStep()).toUriString());
    }

}
