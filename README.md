## An OATH (Open Authentication) Toolkit

A Java-based OATH toolkit providing components for building one-time password authentication systems. Supported technologies include the event-based HOTP algorithm ([RFC4226](https://tools.ietf.org/html/rfc4226)) and the time-based TOTP algorithm ([RFC6238](https://tools.ietf.org/html/rfc6238)).

Presently, the toolkit provides the following components:

* **oath-totp**: A module for generating and validating OTPs.

## Examples

```java
// Generate a 6-digit HOTP using an arbitrary moving factor of 5, 
// and a recommended 160-bit (20 bytes) length key.
String sharedSecretKey = "12345678901234567890";
byte[] key = sharedSecretKey.getBytes("US-ASCII");
HOTP hotp = HOTP.key(key).digits(6).movingFactor(5).build();
// prints "254676"
System.out.println(hotp.value());

// Generate an 8-digit TOTP using a 30 second time step, HMAC-SHA-512,
// and a 64 byte shared secret key.
String sharedSecretKey = "1234567890123456789012345678901234567890123456789012345678901234";
byte[] key = sharedSecretKey.getBytes("US-ASCII");
TOTP totp = TOTP.key(key).timeStep(TimeUnit.SECONDS.toMillis(30)).digits(8).hmacSha512().build();
System.out.println("TOTP = " + totp.value());
```

## Building

You will need a Java Development Kit (1.7) and [Maven](http://maven.apache.org/).
    
To build:

    mvn clean verify
    
To build and activate code coverage metrics:

    mvn clean verify -Pcoverage

## License

The MIT License (MIT)