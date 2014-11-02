package com.lochbridge.oath.otp;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({ TestHmacShaAlgorithm.class, TestHOTP.class, TestHOTPBuilder.class, TestTOTP.class, TestTOTPBuilder.class, TestTOTPValidator.class })
public class AllUnitTestOtpSuite {

}