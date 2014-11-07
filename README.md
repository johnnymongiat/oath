## An OATH (Open Authentication) Toolkit

[![Build Status](https://travis-ci.org/johnnymongiat/oath.svg?branch=master)](https://travis-ci.org/johnnymongiat/oath)
[![Coverage Status](https://coveralls.io/repos/johnnymongiat/oath/badge.png)](https://coveralls.io/r/johnnymongiat/oath)

A Java-based OATH toolkit providing components for building one-time password authentication systems. Supported technologies include the event/counter-based HOTP algorithm ([RFC4226](https://tools.ietf.org/html/rfc4226)) and the time-based TOTP algorithm ([RFC6238](https://tools.ietf.org/html/rfc6238)).

Presently, the toolkit provides the following components:

* **oath-otp**: A module for generating and validating OTPs.
* **oath-otp-keyprovisioning**: A module for providing OTP key provisioning support.

## Examples of Generating/Validating HOTP/TOTP(s)

```java
// Generate a 6-digit HOTP using an arbitrary moving factor of 5, 
// and a recommended 160-bit (20 bytes) length key.
String sharedSecretKey = "12345678901234567890";
byte[] key = sharedSecretKey.getBytes("US-ASCII");
HOTP hotp = HOTP.key(key).digits(6).movingFactor(5).build();
// prints "254676"
System.out.println(hotp.value());
```

```java
// Example of validate a client submitted HOTP.
// Assume the current moving factor of the given client's HOTP is 5, and HOTP's are 6-digits.
String clientHOTPValue = "..."; // The client's HOTP value as received by the authentication server.
byte[] key = ...; // The client's shared secret key.
long currentMovingFactor = 5; // The client's current moving factor as determined by the authentication server.

// Configure a validator to look-ahead an additional 2 times.
HOTPValidationResult result = HOTPValidator.lookAheadWindow(2).validate(key, currentMovingFactor, 6, clientHOTPValue);
if (result.isValid()) {
    // Validation has succeeded, so the authentication server would need to update the client's current moving factor
    // mapping so that subsequent validation requests reference this new/updated value. the new/updated value is
    // captured in the returned HOTPValidationResult via the getNewMovingFactor() method.
    updateMovingFactorForClient(...., result.getNewMovingFactor());
    return;
}
// Validation failed, so the authentication server should ask for another authentication pass of the HOTP validation
// protocol, until the maximum number of authorized attempts (throttling parameter) is reached. Once the maximum number 
// of authorized attempts has been reached, the authentication server should lock out the client's account, and initiate
// a procedure to inform the user.
throw new Exception("HOTP validation attempt failed");
```

```java
// Generate an 8-digit TOTP using a 30 second time step, HMAC-SHA-512,
// and a 64 byte shared secret key.
String sharedSecretKey = "1234567890123456789012345678901234567890123456789012345678901234";
byte[] key = sharedSecretKey.getBytes("US-ASCII");
TOTP totp = TOTP.key(key).timeStep(TimeUnit.SECONDS.toMillis(30)).digits(8).hmacSha512().build();
System.out.println("TOTP = " + totp.value());
```

```java
// The following example illustrates support for Google Authenticator.
// Google Authenticator supports 6-digit TOTPs, and base32 string shared
// secret keys.
//
// Step 1: Generate a 160-bit shared secret key.
byte[] bytes = new byte[20];
SecureRandom random = new SecureRandom();
random.nextBytes(bytes);
String secretKey = BaseEncoding.base32().encode(bytes);

// Step 2: Provision the shared secret key.
// a) Encrypt the 'secretKey' and store it in a secured location.
// b) Deliver the 'secretKey' to the client in a secured fashion (e.g. QR code over SSL)

// Step 3: The client registers the 'secretKey' in their Google Authenticator app. The app
// should now be generating TOTPs every 30 seconds.

// Step 4: The client initiates a two-factor authentication session (i.e. online banking login).
// a) The client provides their username and password (knowledge factor)
// b) The client provides the TOTP code displayed from their Google Authenticator app.
//    (typically b) would be performed as second step after a) has succeeded)
// c) The user submits the request to the server.

// Step 5: The server authenticates the user.
// (assume the username and password were authenticated)
String clientTOTP = "..." // the TOTP value the client submitted.
String encryptedSecretKey = "..." // retrieved from some secured data store.
String secretKey32 = decrypt(encryptedSecretKey); // assume decrypt(...) is implemented
byte[] key = BaseEncoding.base32().decode(secretKey32);
TOTP totp = TOTP.key(key).timeStep(TimeUnit.SECONDS.toMillis(30)).digits(6).hmacSha1().build();
if (totp.value().equals(clientTOTP)) {
    // passed authentication...
} else {
    // failed authentication...
}

// Alternatively, to validate the client TOTP, you can use the TOTPValidator class:
boolean valid = TOTPValidator.window(1).isValid(key, TimeUnit.SECONDS.toMillis(30), 6, 
    HmacShaAlgorithm.HMAC_SHA_1, clientTOTP);
```

## Example of Generating a QR Code Image

```java
String secretKey = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // base32 encoded key.
OTPKey key = new OTPKey(secretKey, OTPType.TOTP);
String issuer = "Acme Corporation";
String label = issuer + ":Alice Smith";

// Create the OTP Auth URI. 
OTPAuthURI uri = OTPAuthURIBuilder.key(key).issuer(issuer).digits(6).timeStep(30000L).build(label, true);
System.out.println(uri.toUriString());
System.out.println(uri.toPlainTextUriString());

// Render a QR Code into a file.
File file = new File("path/to/qrcode.png");
QRCodeWriter.fromURI(uri).width(300).height(300).errorCorrectionLevel(ErrorCorrectionLevel.H)
    .margin(4).imageFormatName("PNG").write(file.toPath());
```

    otpauth://totp/Acme%20Corporation:Alice%20Smith?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Acme%20Corporation&digits=6&period=30

![QRCodeScreenshot](misc/qrcode.png)

## Building

You will need a Java Development Kit (1.7) and [Maven](http://maven.apache.org/).
    
To build:

    mvn clean verify
    
Likewise, if you would want to generate code coverage reports, execute the following commands:

    mvn clean verify -DskipTests
    mvn cobertura:cobertura
    
The code coverage reports will be available under target/site/cobertura directory (open the index.html file).

## License

The MIT License (MIT)