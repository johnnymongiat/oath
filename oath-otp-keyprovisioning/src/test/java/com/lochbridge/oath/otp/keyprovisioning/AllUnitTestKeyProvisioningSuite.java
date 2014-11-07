package com.lochbridge.oath.otp.keyprovisioning;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.lochbridge.oath.otp.keyprovisioning.qrcode.AllUnitTestQRCodeSuite;

@RunWith(Suite.class)
@SuiteClasses({ TestOTPKey.class, TestOTPAuthURI.class, TestOTPAuthURIBuilder.class, AllUnitTestQRCodeSuite.class })
public class AllUnitTestKeyProvisioningSuite {

}