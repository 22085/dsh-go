// Ported from the standalone native certificate tool written for this user
// (2026-11-04, pure Java, no third-party code); only the package changed.
package io.github.ccch1mneyyy.dsh_app.cert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Pure-Java self-signed X.509 certificate generator.
 * No BouncyCastle, no Android-specific APIs, so the same code can be
 * tested on a desktop JVM and runs on the phone with only the JDK.
 * Output is a PKCS12 keystore (usable renamed to .keystore).
 */
public class CertGen {

    public static class Result {
        public byte[] pkcs12;
        public byte[] certBytes;
        public String sha1;
        public String sha256;
        public Date notAfter;
    }

    public static Result generate(String alias, String password,
                                  String cn, String org, String ou,
                                  String city, String state, String country,
                                  int years) throws Exception {
        return generate(alias, password, cn, org, ou, city, state, country, years, 2048);
    }

    public static Result generate(String alias, String password,
                                  String cn, String org, String ou,
                                  String city, String state, String country,
                                  int years, int keySize) throws Exception {
        if (keySize != 2048 && keySize != 4096) keySize = 2048;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();

        String dn = buildDn(cn, org, ou, city, state, country);
        byte[] name = name(dn);

        Date notBefore = new Date();
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        cal.setTime(notBefore);
        cal.add(Calendar.YEAR, years);
        Date notAfter = cal.getTime();

        // SubjectPublicKeyInfo
        byte[] rsaPub = seq(intBytes(pub.getModulus()), intBytes(pub.getPublicExponent()));
        byte[] spki = seq(algId("1.2.840.113549.1.1.1"),
                bitString(rsaPub));

        // Extensions
        List<byte[]> exts = new ArrayList<byte[]>();
        // basicConstraints (critical, CA=false): empty SEQUENCE
        exts.add(extension("2.5.29.19", true, seq()));
        // keyUsage (critical): digitalSignature + keyEncipherment
        exts.add(extension("2.5.29.15", true,
                bitStringRaw(new byte[]{(byte) 0xA0}, 5)));
        // extendedKeyUsage: codeSigning
        exts.add(extension("2.5.29.37", false,
                seq(oidBytes("1.3.6.1.5.5.7.3.3"))));
        // subjectKeyIdentifier: SHA-1 of the RSA public key DER
        MessageDigest sha1md = MessageDigest.getInstance("SHA-1");
        byte[] skid = sha1md.digest(rsaPub);
        exts.add(extension("2.5.29.14", false, octetString(skid)));

        byte[] extSeq = seq(exts.toArray(new byte[0][]));
        byte[] extensions = tlv(0xA3, extSeq);

        byte[] tbs = seq(
                tlv(0xA0, intBytes(BigInteger.valueOf(2))),
                intBytes(BigInteger.valueOf(System.currentTimeMillis())),
                algId("1.2.840.113549.1.1.11"),
                name,
                seq(timeBytes(notBefore), timeBytes(notAfter)),
                name,
                spki,
                extensions);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(kp.getPrivate());
        sig.update(tbs);
        byte[] signature = sig.sign();

        byte[] certDer = seq(tbs, algId("1.2.840.113549.1.1.11"),
                bitString(signature));

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(
                new ByteArrayInputStream(certDer));

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(),
                new Certificate[]{cert});
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ks.store(baos, password.toCharArray());

        Result r = new Result();
        r.pkcs12 = baos.toByteArray();
        r.certBytes = cert.getEncoded();
        r.sha1 = fingerprint(cert, "SHA-1");
        r.sha256 = fingerprint(cert, "SHA-256");
        r.notAfter = notAfter;
        return r;
    }

    private static String buildDn(String cn, String org, String ou,
                                  String city, String state, String country) {
        StringBuilder sb = new StringBuilder();
        appendDn(sb, "CN", cn);
        appendDn(sb, "O", org);
        appendDn(sb, "OU", ou);
        appendDn(sb, "L", city);
        appendDn(sb, "ST", state);
        appendDn(sb, "C", country);
        return sb.toString();
    }

    private static void appendDn(StringBuilder sb, String type, String value) {
        if (value == null || value.trim().isEmpty()) return;
        if (sb.length() > 0) sb.append(',');
        sb.append(type).append('=').append(value.trim());
    }

    // ---- DER helpers ----

    private static byte[] lenBytes(int len) {
        if (len < 128) return new byte[]{(byte) len};
        int n = 0;
        int tmp = len;
        while (tmp > 0) {
            n++;
            tmp >>= 8;
        }
        byte[] out = new byte[1 + n];
        out[0] = (byte) (0x80 | n);
        for (int i = n - 1; i >= 0; i--) {
            out[1 + i] = (byte) (len & 0xFF);
            len >>= 8;
        }
        return out;
    }

    private static byte[] tlv(int tag, byte[] value) {
        byte[] len = lenBytes(value.length);
        byte[] out = new byte[1 + len.length + value.length];
        out[0] = (byte) tag;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(value, 0, out, 1 + len.length, value.length);
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    private static byte[] seq(byte[]... parts) {
        return tlv(0x30, concat(parts));
    }

    private static byte[] intBytes(BigInteger v) {
        return tlv(0x02, v.toByteArray());
    }

    private static byte[] oidBytes(String oid) {
        String[] arcs = oid.split("\\.");
        List<Byte> out = new ArrayList<Byte>();
        int first = Integer.parseInt(arcs[0]) * 40 + Integer.parseInt(arcs[1]);
        out.add((byte) first);
        for (int i = 2; i < arcs.length; i++) {
            long v = Long.parseLong(arcs[i]);
            // base-128, most significant group first
            byte[] buf = new byte[10];
            int n = 0;
            buf[n++] = (byte) (v & 0x7F);
            v >>= 7;
            while (v > 0) {
                buf[n++] = (byte) ((v & 0x7F) | 0x80);
                v >>= 7;
            }
            for (int j = n - 1; j >= 0; j--) out.add(buf[j]);
        }
        byte[] arr = new byte[out.size()];
        for (int i = 0; i < arr.length; i++) arr[i] = out.get(i);
        return tlv(0x06, arr);
    }

    private static byte[] algId(String oid) {
        return seq(oidBytes(oid), tlv(0x05, new byte[0]));
    }

    private static byte[] bitString(byte[] data) {
        byte[] v = new byte[data.length + 1];
        v[0] = 0;
        System.arraycopy(data, 0, v, 1, data.length);
        return tlv(0x03, v);
    }

    private static byte[] bitStringRaw(byte[] data, int unusedBits) {
        byte[] v = new byte[data.length + 1];
        v[0] = (byte) unusedBits;
        System.arraycopy(data, 0, v, 1, data.length);
        return tlv(0x03, v);
    }

    private static byte[] octetString(byte[] data) {
        return tlv(0x04, data);
    }

    private static byte[] extension(String oid, boolean critical, byte[] value) {
        if (critical) {
            return seq(oidBytes(oid), tlv(0x01, new byte[]{(byte) 0xFF}),
                    octetString(value));
        }
        return seq(oidBytes(oid), octetString(value));
    }

    private static byte[] name(String dn) {
        // dn is "CN=x,O=y,..." - build RDNSequence: SEQUENCE of SETs,
        // each SET contains one SEQUENCE { OID, string }.
        List<byte[]> rdns = new ArrayList<byte[]>();
        for (String part : dn.split(",")) {
            int eq = part.indexOf('=');
            String type = part.substring(0, eq).trim();
            String value = part.substring(eq + 1).trim();
            String oid;
            if (type.equals("CN")) oid = "2.5.4.3";
            else if (type.equals("O")) oid = "2.5.4.10";
            else if (type.equals("OU")) oid = "2.5.4.11";
            else if (type.equals("L")) oid = "2.5.4.7";
            else if (type.equals("ST")) oid = "2.5.4.8";
            else if (type.equals("C")) oid = "2.5.4.6";
            else continue;
            byte[] str;
            if (type.equals("C")) {
                str = tlv(0x13, value.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            } else {
                str = tlv(0x0C, value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            byte[] atv = seq(oidBytes(oid), str);
            rdns.add(tlv(0x31, atv));
        }
        return seq(rdns.toArray(new byte[0][]));
    }

    private static byte[] timeBytes(Date d) {
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"), Locale.US);
        cal.setTime(d);
        int year = cal.get(Calendar.YEAR);
        SimpleDateFormat fmt;
        if (year < 2050) {
            fmt = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US);
            fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
            return tlv(0x17, fmt.format(d).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        } else {
            fmt = new SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.US);
            fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
            return tlv(0x18, fmt.format(d).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        }
    }

    private static String fingerprint(Certificate cert, String alg) throws Exception {
        MessageDigest md = MessageDigest.getInstance(alg);
        byte[] digest = md.digest(cert.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < digest.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02X", digest[i]));
        }
        return sb.toString();
    }

    // Desktop test harness: java CertGen <alias> <password> <out.p12>
    public static void main(String[] args) throws Exception {
        String alias = args.length > 0 ? args[0] : "mykey";
        String password = args.length > 1 ? args[1] : "123456";
        String out = args.length > 2 ? args[2] : "/tmp/certgen-test.p12";
        Result r = generate(alias, password, "MyApp", "MyApp", "App",
                "Beijing", "Beijing", "CN", 25);
        java.io.FileOutputStream fos = new java.io.FileOutputStream(out);
        fos.write(r.pkcs12);
        fos.close();
        System.out.println("wrote " + out + " bytes=" + r.pkcs12.length);
        System.out.println("SHA1=" + r.sha1);
        System.out.println("SHA256=" + r.sha256);
        System.out.println("notAfter=" + r.notAfter);
    }
}
