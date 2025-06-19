package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Pair;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;
import android.widget.LinearLayout;
import android.widget.TableRow;
import android.widget.TextView;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.C0148z;
import com.amazon.device.ads.DtbConstants;
import com.comscore.streaming.ContentType;
import com.google.android.gms.ads.internal.client.C1614q;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

/* renamed from: com.google.android.gms.internal.ads.We, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1795We {
    public static AudioManager a;
    public static final int[] b = {1, 2, 3, 6};
    public static final int[] c = {48000, 44100, 32000};
    public static final int[] d = {24000, 22050, 16000};
    public static final int[] e = {2, 1, 2, 3, 3, 4, 4, 5};
    public static final int[] f = {32, 40, 48, 56, 64, 80, 96, ContentType.LONG_FORM_ON_DEMAND, 128, 160, 192, 224, 256, DtbConstants.DEFAULT_PLAYER_WIDTH, 384, 448, com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH, 576, 640};
    public static final int[] g = {69, 87, 104, ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND, 139, 174, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_BACKWARD_COMPATIBILITY, 243, 278, 348, 417, 487, 557, 696, 835, 975, 1114, 1253, 1393};
    public static final String[] h = {"Camera:MotionPhoto", "GCamera:MotionPhoto", "Camera:MicroVideo", "GCamera:MicroVideo"};
    public static final String[] i = {"Camera:MotionPhotoPresentationTimestampUs", "GCamera:MotionPhotoPresentationTimestampUs", "Camera:MicroVideoPresentationTimestampUs", "GCamera:MicroVideoPresentationTimestampUs"};
    public static final String[] j = {"Camera:MicroVideoOffset", "GCamera:MicroVideoOffset"};
    public static final I3 k = new I3("gads:sdk_csi_server", 4, "https://csi.gstatic.com/csi");
    public static final H5 l = new H5(4);
    public static final H5 m = new H5(12);
    public static final H5 n = new H5(16);
    public static final H5 o = new H5(28);
    public static final C2016ej p = new C2016ej(6);
    public static final C2016ej q = new C2016ej(11);
    public static final C2016ej r = new C2016ej(15);
    public static final C2016ej s = new C2016ej(18);
    public static final C2016ej t = new C2016ej(24);
    public static final C2240jq u = new C2240jq(1);
    public static final C2240jq v = new C2240jq(5);
    public static final C2240jq w = new C2240jq(9);
    public static final String[] x = {"GmsCore_OpenSSL", "AndroidOpenSSL", "Conscrypt"};

    public static String A(Context context, String str) {
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        String strC = jVar.y.c(context);
        String strB = jVar.y.b(context);
        if (!str.contains("gmp_app_id") && !TextUtils.isEmpty(strC)) {
            str = d(str, "gmp_app_id", strC).toString();
        }
        return (str.contains("fbs_aiid") || TextUtils.isEmpty(strB)) ? str : d(str, "fbs_aiid", strB).toString();
    }

    public static void B(boolean z) {
        if (!z) {
            throw new IllegalArgumentException();
        }
    }

    public static TextView C(Context context, String str, int i2, int i3, float f2, String str2) {
        TextView textView = new TextView(context);
        textView.setTag(str2);
        K(textView, -2, -2);
        ViewGroup.LayoutParams layoutParams = textView.getLayoutParams();
        if (layoutParams == null) {
            layoutParams = new TableRow.LayoutParams();
        }
        ViewGroup.MarginLayoutParams marginLayoutParams = new ViewGroup.MarginLayoutParams(layoutParams);
        marginLayoutParams.bottomMargin = (int) TypedValue.applyDimension(1, f2, textView.getResources().getDisplayMetrics());
        textView.setLayoutParams(marginLayoutParams);
        textView.setTextAppearance(context, i2);
        textView.setTextColor(i3);
        textView.setText(str);
        return textView;
    }

    public static C1861b1 D(int i2, String str, Kn kn) {
        int iU = kn.u();
        if (kn.u() == 1684108385) {
            kn.k(8);
            return new C1861b1(str, null, AbstractC2330lu.s(kn.a(iU - 16)));
        }
        AbstractC2096gb.J("MetadataUtil", "Failed to parse text attribute: ".concat(androidx.sqlite.db.b.t(i2)));
        return null;
    }

    public static ByteBuffer E(int i2, ByteBuffer byteBuffer) {
        int iLimit = byteBuffer.limit();
        int iPosition = byteBuffer.position();
        int i3 = i2 + iPosition;
        if (i3 < iPosition || i3 > iLimit) {
            throw new BufferUnderflowException();
        }
        byteBuffer.limit(i3);
        try {
            ByteBuffer byteBufferSlice = byteBuffer.slice();
            byteBufferSlice.order(byteBuffer.order());
            byteBuffer.position(i3);
            return byteBufferSlice;
        } finally {
            byteBuffer.limit(iLimit);
        }
    }

    public static void F(Context context) {
        SharedPreferences sharedPreferences = context.getSharedPreferences("admob", 0);
        if (sharedPreferences == null) {
            return;
        }
        sharedPreferences.edit().putInt("init_without_write", 0).putInt("crash_without_write", 0).commit();
    }

    public static void G(boolean z, String str) {
        if (!z) {
            throw new IllegalArgumentException(str);
        }
    }

    public static int H(int i2, int i3) {
        int i4;
        if (i2 < 0 || i2 >= 3 || i3 < 0 || (i4 = i3 >> 1) >= 19) {
            return -1;
        }
        int i5 = c[i2];
        if (i5 == 44100) {
            int i6 = g[i4] + (i3 & 1);
            return i6 + i6;
        }
        int i7 = f[i4];
        return i5 == 32000 ? i7 * 6 : i7 * 4;
    }

    public static int I(Context context, String str) {
        SharedPreferences sharedPreferences = context.getSharedPreferences("admob", 0);
        if (sharedPreferences != null) {
            try {
                return sharedPreferences.getInt(str, 0);
            } catch (ClassCastException unused) {
            }
        }
        return 0;
    }

    public static ByteBuffer J(ByteBuffer byteBuffer) throws IOException {
        if (byteBuffer.remaining() < 4) {
            throw new IOException(android.support.v4.media.session.a.f(byteBuffer.remaining(), "Remaining buffer too short to contain length of length-prefixed field. Remaining: "));
        }
        int i2 = byteBuffer.getInt();
        if (i2 < 0) {
            throw new IllegalArgumentException("Negative length");
        }
        if (i2 <= byteBuffer.remaining()) {
            return E(i2, byteBuffer);
        }
        throw new IOException(androidx.compose.animation.d0.p("Length-prefixed field longer than remaining buffer. Field length: ", i2, ", remaining: ", byteBuffer.remaining()));
    }

    public static void K(View view, int i2, int i3) {
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (layoutParams == null) {
            layoutParams = new TableRow.LayoutParams();
        }
        LinearLayout.LayoutParams layoutParams2 = new LinearLayout.LayoutParams(layoutParams);
        layoutParams2.height = i2;
        layoutParams2.width = i3;
        view.setLayoutParams(layoutParams2);
    }

    public static void L(boolean z) {
        if (!z) {
            throw new IllegalStateException();
        }
    }

    public static void M(int i2, byte[] bArr) {
        bArr[1] = (byte) (i2 & 255);
        bArr[2] = (byte) ((i2 >>> 8) & 255);
        bArr[3] = (byte) ((i2 >>> 16) & 255);
        bArr[4] = (byte) (i2 >> 24);
    }

    public static byte[] N(ByteBuffer byteBuffer) throws IOException {
        int i2 = byteBuffer.getInt();
        if (i2 < 0) {
            throw new IOException("Negative length");
        }
        if (i2 > byteBuffer.remaining()) {
            throw new IOException(androidx.compose.animation.d0.p("Underflow while reading length-prefixed value. Length: ", i2, ", available: ", byteBuffer.remaining()));
        }
        byte[] bArr = new byte[i2];
        byteBuffer.get(bArr);
        return bArr;
    }

    public static X509Certificate[] O(ByteBuffer byteBuffer, HashMap map, CertificateFactory certificateFactory) throws InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, IOException, InvalidKeyException, InvalidAlgorithmParameterException {
        String str;
        Pair pairCreate;
        ByteBuffer byteBufferJ = J(byteBuffer);
        ByteBuffer byteBufferJ2 = J(byteBuffer);
        byte[] bArrN = N(byteBuffer);
        ArrayList arrayList = new ArrayList();
        byte[] bArrN2 = null;
        byte[] bArrN3 = null;
        int i2 = -1;
        int i3 = 0;
        while (byteBufferJ2.hasRemaining()) {
            i3++;
            try {
                ByteBuffer byteBufferJ3 = J(byteBufferJ2);
                if (byteBufferJ3.remaining() < 8) {
                    throw new SecurityException("Signature record too short");
                }
                int i4 = byteBufferJ3.getInt();
                arrayList.add(Integer.valueOf(i4));
                if (i4 != 513 && i4 != 514 && i4 != 769) {
                    switch (i4) {
                        case 257:
                        case 258:
                        case 259:
                        case 260:
                            break;
                        default:
                            continue;
                    }
                }
                if (i2 != -1) {
                    int iR = r(i4);
                    int iR2 = r(i2);
                    if (iR != 1 && iR2 == 1) {
                    }
                }
                bArrN3 = N(byteBufferJ3);
                i2 = i4;
            } catch (IOException e2) {
                e = e2;
                throw new SecurityException(android.support.v4.media.session.a.f(i3, "Failed to parse signature record #"), e);
            } catch (BufferUnderflowException e3) {
                e = e3;
                throw new SecurityException(android.support.v4.media.session.a.f(i3, "Failed to parse signature record #"), e);
            }
        }
        if (i2 == -1) {
            if (i3 == 0) {
                throw new SecurityException("No signatures found");
            }
            throw new SecurityException("No supported signatures found");
        }
        if (i2 == 513 || i2 == 514) {
            str = "EC";
        } else if (i2 != 769) {
            switch (i2) {
                case 257:
                case 258:
                case 259:
                case 260:
                    str = "RSA";
                    break;
                default:
                    throw new IllegalArgumentException("Unknown signature algorithm: 0x".concat(String.valueOf(Long.toHexString(i2))));
            }
        } else {
            str = "DSA";
        }
        if (i2 == 513) {
            pairCreate = Pair.create("SHA256withECDSA", null);
        } else if (i2 == 514) {
            pairCreate = Pair.create("SHA512withECDSA", null);
        } else if (i2 != 769) {
            switch (i2) {
                case 257:
                    pairCreate = Pair.create("SHA256withRSA/PSS", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                    break;
                case 258:
                    pairCreate = Pair.create("SHA512withRSA/PSS", new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
                    break;
                case 259:
                    pairCreate = Pair.create("SHA256withRSA", null);
                    break;
                case 260:
                    pairCreate = Pair.create("SHA512withRSA", null);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown signature algorithm: 0x".concat(String.valueOf(Long.toHexString(i2))));
            }
        } else {
            pairCreate = Pair.create("SHA256withDSA", null);
        }
        String str2 = (String) pairCreate.first;
        AlgorithmParameterSpec algorithmParameterSpec = (AlgorithmParameterSpec) pairCreate.second;
        try {
            PublicKey publicKeyGeneratePublic = KeyFactory.getInstance(str).generatePublic(new X509EncodedKeySpec(bArrN));
            Signature signature = Signature.getInstance(str2);
            signature.initVerify(publicKeyGeneratePublic);
            if (algorithmParameterSpec != null) {
                signature.setParameter(algorithmParameterSpec);
            }
            signature.update(byteBufferJ);
            if (!signature.verify(bArrN3)) {
                throw new SecurityException(String.valueOf(str2).concat(" signature did not verify"));
            }
            byteBufferJ.clear();
            ByteBuffer byteBufferJ4 = J(byteBufferJ);
            ArrayList arrayList2 = new ArrayList();
            int i5 = 0;
            while (byteBufferJ4.hasRemaining()) {
                i5++;
                try {
                    ByteBuffer byteBufferJ5 = J(byteBufferJ4);
                    if (byteBufferJ5.remaining() < 8) {
                        throw new IOException("Record too short");
                    }
                    int i6 = byteBufferJ5.getInt();
                    arrayList2.add(Integer.valueOf(i6));
                    if (i6 == i2) {
                        bArrN2 = N(byteBufferJ5);
                    }
                } catch (IOException e4) {
                    e = e4;
                    throw new IOException(android.support.v4.media.session.a.f(i5, "Failed to parse digest record #"), e);
                } catch (BufferUnderflowException e5) {
                    e = e5;
                    throw new IOException(android.support.v4.media.session.a.f(i5, "Failed to parse digest record #"), e);
                }
            }
            if (!arrayList.equals(arrayList2)) {
                throw new SecurityException("Signature algorithms don't match between digests and signatures records");
            }
            int iR3 = r(i2);
            byte[] bArr = (byte[]) map.put(Integer.valueOf(iR3), bArrN2);
            if (bArr != null && !MessageDigest.isEqual(bArr, bArrN2)) {
                throw new SecurityException(z(iR3).concat(" contents digest does not match the digest specified by a preceding signer"));
            }
            ByteBuffer byteBufferJ6 = J(byteBufferJ);
            ArrayList arrayList3 = new ArrayList();
            int i7 = 0;
            while (byteBufferJ6.hasRemaining()) {
                i7++;
                byte[] bArrN4 = N(byteBufferJ6);
                try {
                    arrayList3.add(new C2597s3((X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(bArrN4)), bArrN4));
                } catch (CertificateException e6) {
                    throw new SecurityException(android.support.v4.media.session.a.f(i7, "Failed to decode certificate #"), e6);
                }
            }
            if (arrayList3.isEmpty()) {
                throw new SecurityException("No certificates listed");
            }
            if (Arrays.equals(bArrN, ((X509Certificate) arrayList3.get(0)).getPublicKey().getEncoded())) {
                return (X509Certificate[]) arrayList3.toArray(new X509Certificate[arrayList3.size()]);
            }
            throw new SecurityException("Public key mismatch between certificate and signature record");
        } catch (InvalidAlgorithmParameterException e7) {
            e = e7;
            throw new SecurityException(android.support.v4.media.session.a.B("Failed to verify ", str2, " signature"), e);
        } catch (InvalidKeyException e8) {
            e = e8;
            throw new SecurityException(android.support.v4.media.session.a.B("Failed to verify ", str2, " signature"), e);
        } catch (NoSuchAlgorithmException e9) {
            e = e9;
            throw new SecurityException(android.support.v4.media.session.a.B("Failed to verify ", str2, " signature"), e);
        } catch (SignatureException e10) {
            e = e10;
            throw new SecurityException(android.support.v4.media.session.a.B("Failed to verify ", str2, " signature"), e);
        } catch (InvalidKeySpecException e11) {
            e = e11;
            throw new SecurityException(android.support.v4.media.session.a.B("Failed to verify ", str2, " signature"), e);
        }
    }

    public static final void P(WebView webView, String str) {
        if (webView == null || TextUtils.isEmpty(str)) {
            return;
        }
        try {
            try {
                webView.evaluateJavascript(str, null);
            } catch (IllegalStateException unused) {
                webView.loadUrl("javascript: " + str);
            }
        } catch (Exception e2) {
            e2.getMessage();
        }
    }

    public static byte[][] Q(int[] iArr, InterfaceC2512q3[] interfaceC2512q3Arr) throws DigestException {
        long j2;
        int i2;
        int length;
        char c2;
        int i3 = 0;
        long jZza = 0;
        while (true) {
            j2 = 1048576;
            if (i3 >= 3) {
                break;
            }
            jZza += (interfaceC2512q3Arr[i3].zza() + 1048575) / 1048576;
            i3++;
        }
        if (jZza >= 2097151) {
            throw new DigestException(androidx.compose.animation.d0.n(jZza, "Too many chunks: "));
        }
        byte[][] bArr = new byte[iArr.length][];
        int i4 = 0;
        while (true) {
            length = iArr.length;
            c2 = 5;
            if (i4 >= length) {
                break;
            }
            int i5 = (int) jZza;
            byte[] bArr2 = new byte[(i(iArr[i4]) * i5) + 5];
            bArr2[0] = 90;
            M(i5, bArr2);
            bArr[i4] = bArr2;
            i4++;
        }
        byte[] bArr3 = new byte[5];
        bArr3[0] = -91;
        MessageDigest[] messageDigestArr = new MessageDigest[length];
        for (int i6 = 0; i6 < iArr.length; i6++) {
            String strZ = z(iArr[i6]);
            try {
                messageDigestArr[i6] = MessageDigest.getInstance(strZ);
            } catch (NoSuchAlgorithmException e2) {
                throw new RuntimeException(strZ.concat(" digest not supported"), e2);
            }
        }
        int i7 = 0;
        int i8 = 0;
        int i9 = 0;
        for (i2 = 3; i7 < i2; i2 = 3) {
            InterfaceC2512q3 interfaceC2512q3 = interfaceC2512q3Arr[i7];
            int i10 = i7;
            long jZza2 = interfaceC2512q3.zza();
            long j3 = 0;
            while (jZza2 > 0) {
                char c3 = c2;
                int i11 = i8;
                int iMin = (int) Math.min(jZza2, j2);
                M(iMin, bArr3);
                for (int i12 = 0; i12 < length; i12++) {
                    messageDigestArr[i12].update(bArr3);
                }
                try {
                    interfaceC2512q3.i(messageDigestArr, j3, iMin);
                    int i13 = 0;
                    while (i13 < iArr.length) {
                        int i14 = iArr[i13];
                        byte[] bArr4 = bArr[i13];
                        int i15 = i(i14);
                        InterfaceC2512q3 interfaceC2512q32 = interfaceC2512q3;
                        MessageDigest messageDigest = messageDigestArr[i13];
                        long j4 = jZza2;
                        int iDigest = messageDigest.digest(bArr4, (i11 * i15) + 5, i15);
                        if (iDigest != i15) {
                            throw new RuntimeException("Unexpected output size of " + messageDigest.getAlgorithm() + " digest: " + iDigest);
                        }
                        i13++;
                        interfaceC2512q3 = interfaceC2512q32;
                        jZza2 = j4;
                    }
                    InterfaceC2512q3 interfaceC2512q33 = interfaceC2512q3;
                    long j5 = iMin;
                    j3 += j5;
                    jZza2 -= j5;
                    i8 = i11 + 1;
                    c2 = c3;
                    interfaceC2512q3 = interfaceC2512q33;
                    j2 = 1048576;
                } catch (IOException e3) {
                    throw new DigestException(androidx.compose.animation.d0.p("Failed to digest chunk #", i11, " of section #", i9), e3);
                }
            }
            i9++;
            i7 = i10 + 1;
            j2 = 1048576;
        }
        byte[][] bArr5 = new byte[iArr.length][];
        for (int i16 = 0; i16 < iArr.length; i16++) {
            int i17 = iArr[i16];
            byte[] bArr6 = bArr[i16];
            String strZ2 = z(i17);
            try {
                bArr5[i16] = MessageDigest.getInstance(strZ2).digest(bArr6);
            } catch (NoSuchAlgorithmException e4) {
                throw new RuntimeException(strZ2.concat(" digest not supported"), e4);
            }
        }
        return bArr5;
    }

    public static X509Certificate[][] R(FileChannel fileChannel, C2554r3 c2554r3) throws CertificateException {
        HashMap map = new HashMap();
        ArrayList arrayList = new ArrayList();
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            try {
                ByteBuffer byteBufferJ = J((ByteBuffer) c2554r3.d);
                int i2 = 0;
                while (byteBufferJ.hasRemaining()) {
                    i2++;
                    try {
                        arrayList.add(O(J(byteBufferJ), map, certificateFactory));
                    } catch (IOException | SecurityException | BufferUnderflowException e2) {
                        throw new SecurityException(AbstractC0147y.c(i2, "Failed to parse/verify signer #", " block"), e2);
                    }
                }
                if (i2 <= 0) {
                    throw new SecurityException("No signers found");
                }
                if (map.isEmpty()) {
                    throw new SecurityException("No content digests found");
                }
                if (map.isEmpty()) {
                    throw new SecurityException("No digests provided");
                }
                long j2 = c2554r3.a;
                C0148z c0148z = new C0148z(fileChannel, 0L, j2, 3);
                long j3 = c2554r3.c;
                long j4 = c2554r3.b;
                C0148z c0148z2 = new C0148z(fileChannel, j4, j3 - j4, 3);
                ByteBuffer byteBufferDuplicate = ((ByteBuffer) c2554r3.e).duplicate();
                byteBufferDuplicate.order(ByteOrder.LITTLE_ENDIAN);
                AbstractC1972di.I(byteBufferDuplicate);
                int iPosition = byteBufferDuplicate.position() + 16;
                if (j2 < 0 || j2 > 4294967295L) {
                    throw new IllegalArgumentException(androidx.compose.animation.d0.n(j2, "uint32 value of out range: "));
                }
                byteBufferDuplicate.putInt(byteBufferDuplicate.position() + iPosition, (int) j2);
                Ts ts = new Ts(byteBufferDuplicate);
                int size = map.size();
                int[] iArr = new int[size];
                Iterator it2 = map.keySet().iterator();
                int i3 = 0;
                while (it2.hasNext()) {
                    iArr[i3] = ((Integer) it2.next()).intValue();
                    i3++;
                }
                try {
                    byte[][] bArrQ = Q(iArr, new InterfaceC2512q3[]{c0148z, c0148z2, ts});
                    for (int i4 = 0; i4 < size; i4++) {
                        int i5 = iArr[i4];
                        if (!MessageDigest.isEqual((byte[]) map.get(Integer.valueOf(i5)), bArrQ[i4])) {
                            throw new SecurityException(z(i5).concat(" digest of contents did not verify"));
                        }
                    }
                    return (X509Certificate[][]) arrayList.toArray(new X509Certificate[arrayList.size()][]);
                } catch (DigestException e3) {
                    throw new SecurityException("Failed to compute digest(s) of contents", e3);
                }
            } catch (IOException e4) {
                throw new SecurityException("Failed to read list of signers", e4);
            }
        } catch (CertificateException e5) {
            throw new RuntimeException("Failed to obtain X.509 CertificateFactory", e5);
        }
    }

    public static float a(String str) {
        if (str.endsWith("%")) {
            return Float.parseFloat(str.substring(0, str.length() - 1)) / 100.0f;
        }
        throw new NumberFormatException("Percentages must end with %");
    }

    public static int b(int i2) {
        switch (i2) {
            case 0:
                return 1;
            case 1:
                return 2;
            case 2:
                return 3;
            case 3:
                return 4;
            case 4:
                return 5;
            case 5:
                return 6;
            case 6:
                return 7;
            case 7:
                return 8;
            case 8:
                return 9;
            case 9:
                return 10;
            case 10:
                return 11;
            case 11:
                return 12;
            case 12:
                return 13;
            case 13:
                return 14;
            default:
                return 0;
        }
    }

    public static int c(int i2, Kn kn) {
        switch (i2) {
            case 1:
                return 192;
            case 2:
            case 3:
            case 4:
            case 5:
                return 576 << (i2 - 2);
            case 6:
                return kn.z() + 1;
            case 7:
                return kn.D() + 1;
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
                return 256 << (i2 - 8);
            default:
                return -1;
        }
    }

    public static Uri d(String str, String str2, String str3) {
        int iIndexOf = str.indexOf("&adurl");
        if (iIndexOf == -1) {
            iIndexOf = str.indexOf("?adurl");
        }
        if (iIndexOf == -1) {
            return Uri.parse(str).buildUpon().appendQueryParameter(str2, str3).build();
        }
        int i2 = iIndexOf + 1;
        StringBuilder sb = new StringBuilder(str.substring(0, i2));
        androidx.compose.ui.node.B.u(sb, str2, SimpleComparison.EQUAL_TO_OPERATION, str3, "&");
        sb.append(str.substring(i2));
        return Uri.parse(sb.toString());
    }

    public static String e(XmlPullParser xmlPullParser, String str) {
        int attributeCount = xmlPullParser.getAttributeCount();
        for (int i2 = 0; i2 < attributeCount; i2++) {
            if (xmlPullParser.getAttributeName(i2).equals(str)) {
                return xmlPullParser.getAttributeValue(i2);
            }
        }
        return null;
    }

    public static void f(int i2, int i3) {
        if (i2 < 0 || i2 >= i3) {
            throw new IndexOutOfBoundsException();
        }
    }

    public static void g(Context context, boolean z) {
        if (z) {
            com.google.android.gms.ads.internal.util.client.i.g("This request is sent from a test device.");
            return;
        }
        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
        com.google.android.gms.ads.internal.util.client.i.g("Use RequestConfiguration.Builder().setTestDeviceIds(Arrays.asList(\"" + com.google.android.gms.ads.internal.util.client.c.o(context) + "\")) to get test ads on this device.");
    }

    public static X509Certificate[][] h(String str) throws IOException {
        Pair pairD;
        RandomAccessFile randomAccessFile = new RandomAccessFile(str, "r");
        try {
            if (randomAccessFile.length() < 22) {
                pairD = null;
            } else {
                pairD = AbstractC1972di.D(randomAccessFile, 0);
                if (pairD == null) {
                    pairD = AbstractC1972di.D(randomAccessFile, 65535);
                }
            }
            if (pairD == null) {
                throw new zzaow("Not an APK file: ZIP End of Central Directory record not found in file with " + randomAccessFile.length() + " bytes");
            }
            ByteBuffer byteBuffer = (ByteBuffer) pairD.first;
            long jLongValue = ((Long) pairD.second).longValue();
            long j2 = jLongValue - 20;
            if (j2 >= 0) {
                randomAccessFile.seek(j2);
                if (randomAccessFile.readInt() == 1347094023) {
                    throw new zzaow("ZIP64 APK not supported");
                }
            }
            AbstractC1972di.I(byteBuffer);
            long j3 = byteBuffer.getInt(byteBuffer.position() + 16) & 4294967295L;
            if (j3 >= jLongValue) {
                throw new zzaow("ZIP Central Directory offset out of range: " + j3 + ". ZIP End of Central Directory offset: " + jLongValue);
            }
            AbstractC1972di.I(byteBuffer);
            if ((byteBuffer.getInt(byteBuffer.position() + 12) & 4294967295L) + j3 != jLongValue) {
                throw new zzaow("ZIP Central Directory is not immediately followed by End of Central Directory");
            }
            if (j3 < 32) {
                throw new zzaow("APK too small for APK Signing Block. ZIP Central Directory offset: " + j3);
            }
            ByteBuffer byteBufferAllocate = ByteBuffer.allocate(24);
            ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;
            byteBufferAllocate.order(byteOrder);
            randomAccessFile.seek(j3 - byteBufferAllocate.capacity());
            randomAccessFile.readFully(byteBufferAllocate.array(), byteBufferAllocate.arrayOffset(), byteBufferAllocate.capacity());
            if (byteBufferAllocate.getLong(8) != 2334950737559900225L || byteBufferAllocate.getLong(16) != 3617552046287187010L) {
                throw new zzaow("No APK Signing Block before ZIP Central Directory");
            }
            long j4 = byteBufferAllocate.getLong(0);
            long j5 = j3;
            if (j4 < byteBufferAllocate.capacity() || j4 > 2147483639) {
                throw new zzaow("APK Signing Block size out of range: " + j4);
            }
            int i2 = (int) (8 + j4);
            long j6 = j5 - i2;
            if (j6 < 0) {
                throw new zzaow("APK Signing Block offset out of range: " + j6);
            }
            ByteBuffer byteBufferAllocate2 = ByteBuffer.allocate(i2);
            byteBufferAllocate2.order(byteOrder);
            randomAccessFile.seek(j6);
            randomAccessFile.readFully(byteBufferAllocate2.array(), byteBufferAllocate2.arrayOffset(), byteBufferAllocate2.capacity());
            long j7 = byteBufferAllocate2.getLong(0);
            if (j7 != j4) {
                throw new zzaow("APK Signing Block sizes in header and footer do not match: " + j7 + " vs " + j4);
            }
            Pair pairCreate = Pair.create(byteBufferAllocate2, Long.valueOf(j6));
            ByteBuffer byteBuffer2 = (ByteBuffer) pairCreate.first;
            long jLongValue2 = ((Long) pairCreate.second).longValue();
            if (byteBuffer2.order() != byteOrder) {
                throw new IllegalArgumentException("ByteBuffer byte order must be little endian");
            }
            int iCapacity = byteBuffer2.capacity() - 24;
            if (iCapacity < 8) {
                throw new IllegalArgumentException("end < start: " + iCapacity + " < 8");
            }
            int iCapacity2 = byteBuffer2.capacity();
            if (iCapacity > byteBuffer2.capacity()) {
                throw new IllegalArgumentException("end > capacity: " + iCapacity + " > " + iCapacity2);
            }
            int iLimit = byteBuffer2.limit();
            int iPosition = byteBuffer2.position();
            try {
                byteBuffer2.position(0);
                byteBuffer2.limit(iCapacity);
                byteBuffer2.position(8);
                ByteBuffer byteBufferSlice = byteBuffer2.slice();
                byteBufferSlice.order(byteBuffer2.order());
                byteBuffer2.position(0);
                byteBuffer2.limit(iLimit);
                byteBuffer2.position(iPosition);
                int i3 = 0;
                while (byteBufferSlice.hasRemaining()) {
                    i3++;
                    if (byteBufferSlice.remaining() < 8) {
                        throw new zzaow("Insufficient data to read size of APK Signing Block entry #" + i3);
                    }
                    long j8 = byteBufferSlice.getLong();
                    if (j8 < 4 || j8 > 2147483647L) {
                        throw new zzaow("APK Signing Block entry #" + i3 + " size out of range: " + j8);
                    }
                    int i4 = (int) j8;
                    int iPosition2 = byteBufferSlice.position() + i4;
                    if (i4 > byteBufferSlice.remaining()) {
                        throw new zzaow("APK Signing Block entry #" + i3 + " size out of range: " + i4 + ", available: " + byteBufferSlice.remaining());
                    }
                    if (byteBufferSlice.getInt() == 1896449818) {
                        X509Certificate[][] x509CertificateArrR = R(randomAccessFile.getChannel(), new C2554r3(E(i4 - 4, byteBufferSlice), jLongValue2, j5, jLongValue, byteBuffer));
                        randomAccessFile.close();
                        return x509CertificateArrR;
                    }
                    long j9 = jLongValue2;
                    long j10 = jLongValue;
                    long j11 = j5;
                    ByteBuffer byteBuffer3 = byteBuffer;
                    byteBufferSlice.position(iPosition2);
                    jLongValue = j10;
                    byteBuffer = byteBuffer3;
                    j5 = j11;
                    jLongValue2 = j9;
                }
                throw new zzaow("No APK Signature Scheme v2 block in APK Signing Block");
            } catch (Throwable th) {
                byteBuffer2.position(0);
                byteBuffer2.limit(iLimit);
                byteBuffer2.position(iPosition);
                throw th;
            }
        } finally {
            try {
                randomAccessFile.close();
            } catch (IOException unused) {
            }
        }
    }

    public static int i(int i2) {
        if (i2 == 1) {
            return 32;
        }
        if (i2 == 2) {
            return 64;
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "Unknown content digest algorthm: "));
    }

    public static int j(Kn kn) {
        int iU = kn.u();
        if (kn.u() == 1684108385) {
            kn.k(8);
            int i2 = iU - 16;
            if (i2 == 1) {
                return kn.z();
            }
            if (i2 == 2) {
                return kn.D();
            }
            if (i2 == 3) {
                return kn.B();
            }
            if (i2 == 4 && (kn.a[kn.b] & 128) == 0) {
                return kn.C();
            }
        }
        AbstractC2096gb.J("MetadataUtil", "Failed to parse data atom to int");
        return -1;
    }

    public static long k(String str) {
        String str2 = Yo.a;
        String[] strArrSplit = str.split("\\.", 2);
        long j2 = 0;
        for (String str3 : strArrSplit[0].split(":", -1)) {
            j2 = (j2 * 60) + Long.parseLong(str3);
        }
        long j3 = j2 * 1000;
        if (strArrSplit.length == 2) {
            String strTrim = strArrSplit[1].trim();
            if (strTrim.length() != 3) {
                throw new IllegalArgumentException("Expected 3 decimal places, got: ".concat(strTrim));
            }
            j3 += Long.parseLong(strTrim);
        }
        return j3 * 1000;
    }

    public static final Intent l(Intent intent, ResolveInfo resolveInfo) {
        Intent intent2 = new Intent(intent);
        ActivityInfo activityInfo = resolveInfo.activityInfo;
        intent2.setClassName(activityInfo.packageName, activityInfo.name);
        return intent2;
    }

    public static Bu m(XmlPullParser xmlPullParser, String str, String str2) throws XmlPullParserException, IOException {
        C2244ju c2244ju = AbstractC2330lu.b;
        AbstractC2543qs.g(4, "initialCapacity");
        Object[] objArrCopyOf = new Object[4];
        int i2 = 0;
        do {
            String strConcat = str.concat(":Item");
            xmlPullParser.next();
            if (w(xmlPullParser, strConcat)) {
                String strConcat2 = str2.concat(":Mime");
                String strConcat3 = str2.concat(":Semantic");
                String strConcat4 = str2.concat(":Length");
                String strConcat5 = str2.concat(":Padding");
                String strE = e(xmlPullParser, strConcat2);
                String strE2 = e(xmlPullParser, strConcat3);
                String strE3 = e(xmlPullParser, strConcat4);
                String strE4 = e(xmlPullParser, strConcat5);
                if (strE == null || strE2 == null) {
                    return Bu.e;
                }
                K0 k0 = new K0(strE3 != null ? Long.parseLong(strE3) : 0L, strE4 != null ? Long.parseLong(strE4) : 0L, strE);
                int length = objArrCopyOf.length;
                int i3 = i2 + 1;
                int iH = AbstractC2027eu.h(length, i3);
                if (iH > length) {
                    objArrCopyOf = Arrays.copyOf(objArrCopyOf, iH);
                }
                objArrCopyOf[i2] = k0;
                i2 = i3;
            }
        } while (!q(xmlPullParser, str.concat(":Directory")));
        return AbstractC2330lu.m(i2, objArrCopyOf);
    }

    public static void n(int i2, String str, Throwable th) {
        com.google.android.gms.ads.internal.util.client.i.g("Ad failed to load : " + i2);
        com.google.android.gms.ads.internal.util.A.m();
        if (i2 == 3) {
            return;
        }
        com.google.android.gms.ads.internal.j.C.h.g(str, th);
    }

    public static void o(WebView webView, String str, Object... objArr) {
        if (webView != null) {
            StringBuilder sb = new StringBuilder(128);
            sb.append("if(window.omidBridge!==undefined){omidBridge.");
            sb.append(str);
            sb.append("(");
            for (Object obj : objArr) {
                if (obj == null) {
                    sb.append("null");
                } else if (obj instanceof String) {
                    String string = obj.toString();
                    if (string.startsWith("{")) {
                        sb.append(string);
                    } else {
                        sb.append('\"');
                        sb.append(string);
                        sb.append('\"');
                    }
                } else {
                    sb.append(obj);
                }
                sb.append(",");
            }
            sb.setLength(sb.length() - 1);
            sb.append(")}");
            String string2 = sb.toString();
            Handler handler = webView.getHandler();
            if (handler == null) {
                handler = new Handler(Looper.getMainLooper());
            }
            if (Looper.myLooper() == handler.getLooper()) {
                P(webView, string2);
            } else {
                handler.post(new RunnableC2793wl(13, webView, string2));
            }
        }
    }

    public static void p(Object obj) {
        if (obj == null) {
            throw new IllegalStateException();
        }
    }

    public static boolean q(XmlPullParser xmlPullParser, String str) {
        return xmlPullParser.getEventType() == 3 && xmlPullParser.getName().equals(str);
    }

    public static int r(int i2) {
        if (i2 == 513) {
            return 1;
        }
        if (i2 == 514) {
            return 2;
        }
        if (i2 == 769) {
            return 1;
        }
        switch (i2) {
            case 257:
            case 259:
                return 1;
            case 258:
            case 260:
                return 2;
            default:
                throw new IllegalArgumentException("Unknown signature algorithm: 0x".concat(String.valueOf(Long.toHexString(i2))));
        }
    }

    public static synchronized AudioManager s(Context context) {
        try {
            Context applicationContext = context.getApplicationContext();
            if (applicationContext != null) {
                a = null;
            }
            AudioManager audioManager = a;
            if (audioManager != null) {
                return audioManager;
            }
            Looper looperMyLooper = Looper.myLooper();
            if (looperMyLooper != null && looperMyLooper != Looper.getMainLooper()) {
                C1973dj c1973dj = new C1973dj();
                AbstractC1972di.d().execute(new Qv(20, applicationContext, c1973dj));
                c1973dj.a();
                AudioManager audioManager2 = a;
                if (audioManager2 != null) {
                    return audioManager2;
                }
                throw null;
            }
            AudioManager audioManager3 = (AudioManager) applicationContext.getSystemService("audio");
            a = audioManager3;
            if (audioManager3 != null) {
                return audioManager3;
            }
            throw null;
        } catch (Throwable th) {
            throw th;
        }
    }

    public static W0 t(int i2, String str, Kn kn, boolean z, boolean z2) {
        int iJ = j(kn);
        if (z2) {
            iJ = Math.min(1, iJ);
        }
        if (iJ >= 0) {
            return z ? new C1861b1(str, null, AbstractC2330lu.s(Integer.toString(iJ))) : new T0("und", str, Integer.toString(iJ));
        }
        AbstractC2096gb.J("MetadataUtil", "Failed to parse uint8 attribute: ".concat(androidx.sqlite.db.b.t(i2)));
        return null;
    }

    public static String u(String str, Context context, boolean z, HashMap map) {
        C1739Nc c1739Nc;
        String strA;
        C2601s7 c2601s7 = AbstractC2773w7.u0;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && !z) {
            return str;
        }
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        if (!jVar.y.e(context) || TextUtils.isEmpty(str) || (strA = (c1739Nc = jVar.y).a(context)) == null) {
            return str;
        }
        C2601s7 c2601s72 = AbstractC2773w7.n0;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        String str2 = (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72);
        boolean zBooleanValue = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.m0)).booleanValue();
        com.google.android.gms.ads.internal.util.F f2 = jVar.c;
        if (zBooleanValue && str.contains(str2)) {
            f2.getClass();
            if (com.google.android.gms.ads.internal.util.F.w(str, f2.a, (String) rVar.c.a(AbstractC2773w7.j0))) {
                Map map2 = (Map) map.get("_ac");
                c1739Nc.getClass();
                c1739Nc.k(context, "_ac", strA, C1739Nc.f(map2));
                return A(context, str).replace(str2, strA);
            }
            f2.getClass();
            if (!com.google.android.gms.ads.internal.util.F.w(str, f2.b, (String) rVar.c.a(AbstractC2773w7.k0))) {
                return str;
            }
            Map map3 = (Map) map.get("_ai");
            c1739Nc.getClass();
            c1739Nc.k(context, "_ai", strA, C1739Nc.f(map3));
            return A(context, str).replace(str2, strA);
        }
        if (str.contains("fbs_aeid") || ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.l0)).booleanValue()) {
            return str;
        }
        f2.getClass();
        if (com.google.android.gms.ads.internal.util.F.w(str, f2.a, (String) rVar.c.a(AbstractC2773w7.j0))) {
            Map map4 = (Map) map.get("_ac");
            c1739Nc.getClass();
            c1739Nc.k(context, "_ac", strA, C1739Nc.f(map4));
            return d(A(context, str), "fbs_aeid", strA).toString();
        }
        f2.getClass();
        if (!com.google.android.gms.ads.internal.util.F.w(str, f2.b, (String) rVar.c.a(AbstractC2773w7.k0))) {
            return str;
        }
        Map map5 = (Map) map.get("_ai");
        c1739Nc.getClass();
        c1739Nc.k(context, "_ai", strA, C1739Nc.f(map5));
        return d(A(context, str), "fbs_aeid", strA).toString();
    }

    /* JADX WARN: Removed duplicated region for block: B:51:0x00a4  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean v(com.google.android.gms.internal.ads.Kn r24, com.google.android.gms.internal.ads.Z r25, int r26, androidx.compose.foundation.lazy.layout.C0429a r27) {
        /*
            Method dump skipped, instructions count: 196
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC1795We.v(com.google.android.gms.internal.ads.Kn, com.google.android.gms.internal.ads.Z, int, androidx.compose.foundation.lazy.layout.a):boolean");
    }

    public static boolean w(XmlPullParser xmlPullParser, String str) {
        return xmlPullParser.getEventType() == 2 && xmlPullParser.getName().equals(str);
    }

    public static final ResolveInfo x(Intent intent, ArrayList arrayList, Context context) {
        ResolveInfo resolveInfo = null;
        try {
            PackageManager packageManager = context.getPackageManager();
            if (packageManager == null) {
                return null;
            }
            List<ResolveInfo> listQueryIntentActivities = packageManager.queryIntentActivities(intent, 65536);
            ResolveInfo resolveInfoResolveActivity = packageManager.resolveActivity(intent, 65536);
            if (listQueryIntentActivities != null && resolveInfoResolveActivity != null) {
                int i2 = 0;
                while (true) {
                    if (i2 >= listQueryIntentActivities.size()) {
                        break;
                    }
                    if (resolveInfoResolveActivity.activityInfo.name.equals(listQueryIntentActivities.get(i2).activityInfo.name)) {
                        resolveInfo = resolveInfoResolveActivity;
                        break;
                    }
                    i2++;
                }
            }
            arrayList.addAll(listQueryIntentActivities);
            return resolveInfo;
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.j.C.h.h("OpenSystemBrowserHandler.getDefaultBrowserResolverForIntent", th);
            return resolveInfo;
        }
    }

    public static C1861b1 y(int i2, String str, Kn kn) {
        int iU = kn.u();
        if (kn.u() == 1684108385 && iU >= 22) {
            kn.k(10);
            int iD = kn.D();
            if (iD > 0) {
                StringBuilder sb = new StringBuilder();
                sb.append(iD);
                String string = sb.toString();
                int iD2 = kn.D();
                if (iD2 > 0) {
                    string = string + "/" + iD2;
                }
                return new C1861b1(str, null, AbstractC2330lu.s(string));
            }
        }
        AbstractC2096gb.J("MetadataUtil", "Failed to parse index/count attribute: ".concat(androidx.sqlite.db.b.t(i2)));
        return null;
    }

    public static String z(int i2) {
        if (i2 == 1) {
            return "SHA-256";
        }
        if (i2 == 2) {
            return "SHA-512";
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "Unknown content digest algorthm: "));
    }
}
