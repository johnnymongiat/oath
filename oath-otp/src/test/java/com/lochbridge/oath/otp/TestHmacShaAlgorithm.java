package com.lochbridge.oath.otp;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class TestHmacShaAlgorithm {

    @Test(expected = IllegalArgumentException.class)
    public void fromShouldFailWhenNoMatch() {
        HmacShaAlgorithm.from("foobar");
    }

    @Test
    public void fromShouldSucceed() {
        assertEquals(HmacShaAlgorithm.HMAC_SHA_1, HmacShaAlgorithm.from(HmacShaAlgorithm.HMAC_SHA_1.getAlgorithm()));
    }

    @Test
    public void toStringShouldBeEquivalentToGetAlgorithm() {
        assertEquals(HmacShaAlgorithm.HMAC_SHA_1.getAlgorithm(), HmacShaAlgorithm.HMAC_SHA_1.toString());
    }

    @Test
    public void valueOfShouldSucceed() {
        assertEquals(HmacShaAlgorithm.HMAC_SHA_1, HmacShaAlgorithm.valueOf("HMAC_SHA_1"));
    }

}
