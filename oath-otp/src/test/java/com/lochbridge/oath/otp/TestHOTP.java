package com.lochbridge.oath.otp;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class TestHOTP {

    private HOTP hotp;

    @Before
    public void setUp() {
        hotp = new HOTP("123456", 6, 0);
    }

    @Test
    public void hashCodeShouldBeBasedOnTOTPValue() {
        assertEquals(hotp.value().hashCode(), hotp.hashCode());
    }

    @Test
    public void equalsShouldBeBasedOnTOTPValue() {
        assertEquals(hotp, new HOTP(hotp.value(), 8, 1));
        assertEquals(hotp, hotp);
        assertFalse(hotp.equals(null));
        assertFalse(hotp.equals(hotp.value()));
    }

}
