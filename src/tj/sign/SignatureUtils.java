package tj.sign;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import sun.security.pkcs.PKCS7;

/**
 * <pre>
 * 1 MANIFEST.MF中的各SHA-1值 == SHA-1(除META-INF目录外的文件)；
 * 2 CERT.SF中各值 == (SHA-1 + Base64)(MANIFEST.MF文件及各子项)；
 * 3 CERT.RSA/DSA/EC == 公钥＋加密算法信息等；
 * </pre>
 *
 * @author sp00f
 */
public class SignatureUtils {

    private final byte[] mSignature;
    private int mHashCode;
    private boolean mHaveHashCode;

    /**
     * Create Signature from an existing raw byte array.
     */
    public SignatureUtils(byte[] signature) {
        mSignature = (byte[]) signature.clone();
    }

    private static final int parseHexDigit(int nibble) {
        if ('0' <= nibble && nibble <= '9') {
            return nibble - '0';
        } else if ('a' <= nibble && nibble <= 'f') {
            return nibble - 'a' + 10;
        } else if ('A' <= nibble && nibble <= 'F') {
            return nibble - 'A' + 10;
        } else {
            throw new IllegalArgumentException("Invalid character " + nibble + " in hex string");
        }
    }

    /**
     * Create Signature from a text representation previously returned by
     * {@link #toChars} or {@link #toCharsString()}. Signatures are expected to
     * be a hex-encoded ASCII string.
     *
     * @param text hex-encoded string representing the signature
     * @throws IllegalArgumentException when signature is odd-length
     */
    public SignatureUtils(String text) {
        final byte[] input = text.getBytes();
        final int N = input.length;

        if (N % 2 != 0) {
            throw new IllegalArgumentException("text size " + N + " is not even");
        }

        final byte[] sig = new byte[N / 2];
        int sigIndex = 0;

        for (int i = 0; i < N;) {
            final int hi = parseHexDigit(input[i++]);
            final int lo = parseHexDigit(input[i++]);
            sig[sigIndex++] = (byte) ((hi << 4) | lo);
        }

        mSignature = sig;
    }

    /**
     * Encode the Signature as ASCII text.
     */
    public char[] toChars() {
        return toChars(null, null);
    }

    /**
     * Encode the Signature as ASCII text in to an existing array.
     *
     * @param existingArray Existing char array or null.
     * @param outLen Output parameter for the number of characters written in to
     * the array.
     * @return Returns either <var>existingArray</var> if it was large enough to
     * hold the ASCII representation, or a newly created char[] array if needed.
     */
    public char[] toChars(char[] existingArray, int[] outLen) {
        byte[] sig = mSignature;
        final int N = sig.length;
        final int N2 = N * 2;
        char[] text = existingArray == null || N2 > existingArray.length
                ? new char[N2] : existingArray;
        for (int j = 0; j < N; j++) {
            byte v = sig[j];
            int d = (v >> 4) & 0xf;
            text[j * 2] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
            d = v & 0xf;
            text[j * 2 + 1] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
        }
        if (outLen != null) {
            outLen[0] = N;
        }
        return text;
    }

    /**
     * Return the result of {@link #toChars()} as a String.
     */
    public String toCharsString() {
        String str = new String(toChars());
        return str;
    }

    /**
     * @return the contents of this signature as a byte array.
     */
    public byte[] toByteArray() {
        byte[] bytes = new byte[mSignature.length];
        System.arraycopy(mSignature, 0, bytes, 0, mSignature.length);
        return bytes;
    }

    public boolean equals(Object obj) {
        try {
            if (obj != null) {
                SignatureUtils other = (SignatureUtils) obj;
                return this == other || Arrays.equals(mSignature, other.mSignature);
            }
        } catch (ClassCastException e) {
        }
        return false;
    }

    public int hashCode() {
        if (mHaveHashCode) {
            return mHashCode;
        }
        mHashCode = Arrays.hashCode(mSignature);
        mHaveHashCode = true;
        return mHashCode;
    }

    public int describeContents() {
        return 0;
    }

    /**
     * Test if given {@link Signature} sets are exactly equal.
     *
     * @hide
     */
    public static boolean areExactMatch(SignatureUtils[] a, SignatureUtils[] b) {
        return ArrayUtils.containsAll(a, b) && ArrayUtils.containsAll(b, a);
    }

    /**
     * 获取公钥 Returns the public key for this signature.
     *
     * @throws CertificateException when Signature isn't a valid X.509
     * certificate; shouldn't happen.
     * @hide
     */
    public PublicKey getPublicKey() throws CertificateException {
        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        final ByteArrayInputStream bais = new ByteArrayInputStream(mSignature);
        final Certificate cert = certFactory.generateCertificate(bais);
        X509Certificate xcert = (X509Certificate) cert;
        System.out.println("issuer:" + xcert.getIssuerDN());
        System.out.println("subject:" + xcert.getSubjectDN());
        System.out.println(xcert.getPublicKey());
        return cert.getPublicKey();
    }

    public static X509Certificate readSignatureBlock(InputStream in) throws IOException, GeneralSecurityException {
        PKCS7 pkcs7 = new PKCS7(in);
        return pkcs7.getCertificates()[0];
    }

    /**
     * parse sign from real file
     *
     * @param fpath sign directory
     * @return sign byte
     * @throws Exception
     */
    public static byte[] parseCertToString(String fpath) throws Exception {

        X509Certificate publicKey = readSignatureBlock(new FileInputStream(new File(fpath)));

        System.out.println("issuer:" + publicKey.getIssuerDN());
        System.out.println("subject:" + publicKey.getSubjectDN());
        System.out.println("subject DN: " + publicKey.getSubjectX500Principal());
        System.out.println("publicKey: " + publicKey.getPublicKey());

        return publicKey.getEncoded();
    }

    /**
     * parse sign from classpath
     *
     * @param certName cert name
     * @return sign byte
     * @throws Exception
     */
    public static byte[] parseCertToString1(String certName) throws Exception {
        if (certName == null) {
            certName = "./CERT.RSA";
        }

        X509Certificate publicKey = null;

        try {
            publicKey = readSignatureBlock(new FileInputStream(new File(certName)));
        } catch (NullPointerException e) {
            String path = SignatureUtils.class.getClass().getResource(certName).getFile();
            publicKey = readSignatureBlock(new FileInputStream(new File(path)));
        }

        System.out.println("issuer:" + publicKey.getIssuerDN());
        System.out.println("subject:" + publicKey.getSubjectDN());
        System.out.println("subject DN:" + publicKey.getSubjectX500Principal());
        System.out.println("publicKey: " + publicKey.getPublicKey());

        return publicKey.getEncoded();
    }

    public static byte[] parseCertBytes(InputStream in) throws Exception {
        X509Certificate publicKey = readSignatureBlock(in);

        System.out.println("issuer:" + publicKey.getIssuerDN());
        System.out.println("subject:" + publicKey.getSubjectDN());
        System.out.println("subject DN:" + publicKey.getSubjectX500Principal());
        System.out.println("publicKey: " + publicKey.getPublicKey());

        return publicKey.getEncoded();
    }

    public static String xchSignBytesToStr(byte[] b) {
        SignatureUtils sigsss = new SignatureUtils(b);
        return sigsss.toCharsString();
    }

    public static void writeSignStrToFile(File file, String sign) throws IOException {
        if (!file.exists()) {
            file.createNewFile();
        }

        FileWriter fw = new FileWriter(file);
        fw.write(sign);
        fw.flush();
        fw.close();

    }

    /**
     * parse sign from apk
     *
     * @param zipfile
     * @param entryName
     * @return
     * @throws Exception
     */
    public static byte[] getZipIn(String zipfile, String entryName) throws Exception {
        byte[] sign = null;
        ZipFile zf = new ZipFile(zipfile);
        InputStream in = new BufferedInputStream(new FileInputStream(zipfile));
        ZipInputStream zin = new ZipInputStream(in);
        ZipEntry ze;

        while ((ze = zin.getNextEntry()) != null) {
            if (ze.isDirectory()) {
                continue;
            } else {
                if (ze.getName().equalsIgnoreCase(entryName)) {
                    sign = parseCertBytes(zf.getInputStream(ze));
                    break;
                }
            }
            zin.closeEntry();
        }

        in.close();
        zin.close();

        return sign;
    }

//    public static void main(String[] args) throws Exception {
//        String path = SignatureUtils.class.getClass().getResource("/CERT.RSA").getFile();
//        System.out.println(xchSignBytesToStr(getZipIn("d:/poke/test.apk", "META-INF/CERT.RSA")));
//    }

}
