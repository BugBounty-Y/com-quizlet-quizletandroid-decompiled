package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Environment;
import android.text.TextUtils;
import android.util.Base64;
import androidx.core.view.AbstractC1047f0;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: classes2.dex */
public final class C1 implements InterfaceC2294l0, InterfaceC2001eB, Bt, D, K, Q, W, S1, Z1, TA {
    public static final C1 b;
    public static final C1 c;
    public static Cipher e;
    public final /* synthetic */ int a;
    public static final C1 d = new C1(1);
    public static final Object f = new Object();
    public static final Object g = new Object();
    public static final C1 h = new C1(3);
    public static final byte[] i = {61, 122, 18, 35, 1, -102, -93, -99, -98, -96, -29, 67, 106, -73, -64, -119, 107, -5, 79, -74, 121, -12, -34, 95, -25, -62, 63, 50, 108, -113, -103, 74};
    public static final byte[] j = {-110, -13, -34, 70, -83, 43, 97, 21, -44, 16, -54, -125, -28, -57, -125, -127, -7, 17, 102, -69, 116, -121, -79, 43, -13, 120, 58, 55, -29, -108, 95, 83};
    public static final C1 k = new C1(5);
    public static final C1 l = new C1(6);
    public static final C1 m = new C1(8);
    public static final C1 n = new C1(9);

    static {
        int i2 = 0;
        b = new C1(i2);
        c = new C1(i2);
    }

    public /* synthetic */ C1(int i2) {
        this.a = i2;
    }

    private final void i() {
    }

    private final void k(InterfaceC2122h0 interfaceC2122h0) {
    }

    public static final SharedPreferences l(Context context) {
        try {
            return context.getSharedPreferences("google_ads_flags", 0);
        } catch (IllegalStateException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("", e2);
            return null;
        }
    }

    public static androidx.compose.ui.text.android.selection.f m(B3 b3, Map map) throws Throwable {
        HashMap map2 = new HashMap();
        map2.putAll(map);
        map2.putAll(b3.c());
        URL url = new URL(b3.c);
        HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
        httpURLConnection.setInstanceFollowRedirects(HttpURLConnection.getFollowRedirects());
        int i2 = b3.l.a;
        httpURLConnection.setConnectTimeout(i2);
        httpURLConnection.setReadTimeout(i2);
        boolean z = false;
        httpURLConnection.setUseCaches(false);
        httpURLConnection.setDoInput(true);
        "https".equals(url.getProtocol());
        try {
            for (String str : map2.keySet()) {
                httpURLConnection.setRequestProperty(str, (String) map2.get(str));
            }
            if (b3.b != 0) {
                httpURLConnection.setRequestMethod("POST");
                byte[] bArrK = b3.k();
                if (bArrK != null) {
                    httpURLConnection.setDoOutput(true);
                    if (!httpURLConnection.getRequestProperties().containsKey("Content-Type")) {
                        httpURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
                    }
                    DataOutputStream dataOutputStream = new DataOutputStream(httpURLConnection.getOutputStream());
                    dataOutputStream.write(bArrK);
                    dataOutputStream.close();
                }
            } else {
                httpURLConnection.setRequestMethod("GET");
            }
            int responseCode = httpURLConnection.getResponseCode();
            if (responseCode == -1) {
                throw new IOException("Could not retrieve response code from HttpUrlConnection.");
            }
            if ((responseCode >= 100 && responseCode < 200) || responseCode == 204 || responseCode == 304) {
                androidx.compose.ui.text.android.selection.f fVar = new androidx.compose.ui.text.android.selection.f(responseCode, v(httpURLConnection.getHeaderFields()), -1, null);
                httpURLConnection.disconnect();
                return fVar;
            }
            try {
                return new androidx.compose.ui.text.android.selection.f(responseCode, v(httpURLConnection.getHeaderFields()), httpURLConnection.getContentLength(), new com.android.volley.toolbox.e(httpURLConnection, 1));
            } catch (Throwable th) {
                th = th;
                z = true;
                if (!z) {
                    httpURLConnection.disconnect();
                }
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    public static final C2257k6 o(Context context, zzbbf zzbbfVar) {
        com.bumptech.glide.manager.p pVar = new com.bumptech.glide.manager.p(context, 7);
        C2257k6 c2257k6 = new C2257k6(pVar);
        C2326lq c2326lq = new C2326lq(pVar, zzbbfVar, c2257k6, 6);
        Fi fi = new Fi(pVar, false, c2257k6, 7);
        synchronized (pVar.c) {
            C2172i6 c2172i6 = new C2172i6(context, com.google.android.gms.ads.internal.j.C.t.o(), c2326lq, fi);
            pVar.b = c2172i6;
            c2172i6.c();
        }
        return c2257k6;
    }

    public static /* bridge */ C2691uB r(Object obj) {
        OA oa = (OA) obj;
        C2691uB c2691uB = oa.zzt;
        if (c2691uB != C2691uB.f) {
            return c2691uB;
        }
        C2691uB c2691uBB = C2691uB.b();
        oa.zzt = c2691uBB;
        return c2691uBB;
    }

    public static String s(byte[] bArr, byte[] bArr2) throws zzavs {
        byte[] bArrDoFinal;
        byte[] iv;
        int length = bArr.length;
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");
            synchronized (f) {
                x().init(1, secretKeySpec, (SecureRandom) null);
                bArrDoFinal = x().doFinal(bArr2);
                iv = x().getIV();
            }
            int length2 = bArrDoFinal.length + iv.length;
            ByteBuffer byteBufferAllocate = ByteBuffer.allocate(length2);
            byteBufferAllocate.put(iv).put(bArrDoFinal);
            byteBufferAllocate.flip();
            byte[] bArr3 = new byte[length2];
            byteBufferAllocate.get(bArr3);
            return Base64.encodeToString(bArr3, 2);
        } catch (InvalidKeyException e2) {
            throw new zzavs(e2);
        } catch (NoSuchAlgorithmException e3) {
            throw new zzavs(e3);
        } catch (BadPaddingException e4) {
            throw new zzavs(e4);
        } catch (IllegalBlockSizeException e5) {
            throw new zzavs(e5);
        } catch (NoSuchPaddingException e6) {
            throw new zzavs(e6);
        }
    }

    public static final void t(com.google.android.datatransport.cct.internal.s sVar, com.quizlet.data.repository.metering.j jVar) {
        File externalStorageDirectory;
        Context context = (Context) jVar.c;
        if (context == null) {
            throw new IllegalArgumentException("Context can't be null. Please set up context in CsiConfiguration.");
        }
        String str = (String) jVar.d;
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("AfmaVersion can't be null or empty. Please set up afmaVersion in CsiConfiguration.");
        }
        LinkedHashMap linkedHashMap = (LinkedHashMap) jVar.b;
        sVar.e = context;
        sVar.f = str;
        sVar.a = (String) jVar.a;
        AtomicBoolean atomicBoolean = new AtomicBoolean(false);
        sVar.h = atomicBoolean;
        atomicBoolean.set(((Boolean) S7.c.o()).booleanValue());
        if (((AtomicBoolean) sVar.h).get() && (externalStorageDirectory = Environment.getExternalStorageDirectory()) != null) {
            sVar.i = new File(new File(externalStorageDirectory, "sdk_csi_data.txt").getPath());
        }
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            ((LinkedHashMap) sVar.c).put((String) entry.getKey(), (String) entry.getValue());
        }
        AbstractC2270kd.a.execute(new RunnableC1989e(sVar, 10));
        HashMap map = (HashMap) sVar.d;
        C2859y7 c2859y7 = C2859y7.c;
        map.put("action", c2859y7);
        map.put("ad_format", c2859y7);
        map.put("e", C2859y7.d);
    }

    public static boolean u(File file) throws GeneralSecurityException {
        try {
            X509Certificate[][] x509CertificateArrH = AbstractC1795We.h(file.getAbsolutePath());
            if (x509CertificateArrH.length != 1) {
                throw new GeneralSecurityException("APK has more than one signature.");
            }
            byte[] bArrDigest = MessageDigest.getInstance("SHA-256").digest(x509CertificateArrH[0][0].getEncoded());
            return Arrays.equals(i, bArrDigest) || (!"user".equals(Build.TYPE) && Arrays.equals(j, bArrDigest));
        } catch (zzaow e2) {
            throw new GeneralSecurityException("Package is not signed", e2);
        } catch (IOException | RuntimeException e3) {
            throw new GeneralSecurityException("Failed to verify signatures", e3);
        }
    }

    public static ArrayList v(Map map) {
        ArrayList arrayList = new ArrayList(map.size());
        for (Map.Entry entry : map.entrySet()) {
            if (entry.getKey() != null) {
                Iterator it2 = ((List) entry.getValue()).iterator();
                while (it2.hasNext()) {
                    arrayList.add(new C2812x3((String) entry.getKey(), (String) it2.next()));
                }
            }
        }
        return arrayList;
    }

    public static byte[] w(String str, byte[] bArr) throws zzavs {
        byte[] bArrDoFinal;
        int length = bArr.length;
        try {
            byte[] bArrDecode = Base64.decode(str, 2);
            if (bArrDecode.length == 0 && str.length() > 0) {
                throw new IllegalArgumentException("Unable to decode ".concat(str));
            }
            int length2 = bArrDecode.length;
            if (length2 <= 16) {
                throw new zzavs();
            }
            ByteBuffer byteBufferAllocate = ByteBuffer.allocate(length2);
            byteBufferAllocate.put(bArrDecode);
            byteBufferAllocate.flip();
            byte[] bArr2 = new byte[16];
            byte[] bArr3 = new byte[length2 - 16];
            byteBufferAllocate.get(bArr2);
            byteBufferAllocate.get(bArr3);
            SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");
            synchronized (f) {
                x().init(2, secretKeySpec, new IvParameterSpec(bArr2));
                bArrDoFinal = x().doFinal(bArr3);
            }
            return bArrDoFinal;
        } catch (IllegalArgumentException e2) {
            throw new zzavs(e2);
        } catch (InvalidAlgorithmParameterException e3) {
            throw new zzavs(e3);
        } catch (InvalidKeyException e4) {
            throw new zzavs(e4);
        } catch (NoSuchAlgorithmException e5) {
            throw new zzavs(e5);
        } catch (BadPaddingException e6) {
            throw new zzavs(e6);
        } catch (IllegalBlockSizeException e7) {
            throw new zzavs(e7);
        } catch (NoSuchPaddingException e8) {
            throw new zzavs(e8);
        }
    }

    public static final Cipher x() {
        Cipher cipher;
        synchronized (g) {
            try {
                if (e == null) {
                    e = Cipher.getInstance("AES/CBC/PKCS5Padding");
                }
                cipher = e;
            } catch (Throwable th) {
                throw th;
            }
        }
        return cipher;
    }

    public static boolean y(int i2, androidx.compose.runtime.changelist.K k2, Object obj) throws zzgzh {
        int i3 = k2.b;
        int i4 = i3 >>> 3;
        int i5 = i3 & 7;
        AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) k2.e;
        if (i5 == 0) {
            k2.y(0);
            ((C2691uB) obj).c(i4 << 3, Long.valueOf(abstractC1047f0.a0()));
            return true;
        }
        if (i5 == 1) {
            k2.y(1);
            ((C2691uB) obj).c((i4 << 3) | 1, Long.valueOf(abstractC1047f0.Z()));
            return true;
        }
        if (i5 == 2) {
            k2.y(2);
            ((C2691uB) obj).c((i4 << 3) | 2, abstractC1047f0.e0());
            return true;
        }
        if (i5 != 3) {
            if (i5 == 4) {
                if (i2 != 0) {
                    return false;
                }
                throw new zzgzh("Protocol message end-group tag did not match expected tag.");
            }
            if (i5 != 5) {
                throw new zzgzg();
            }
            k2.y(5);
            ((C2691uB) obj).c(5 | (i4 << 3), Integer.valueOf(abstractC1047f0.T()));
            return true;
        }
        C2691uB c2691uBB = C2691uB.b();
        int i6 = i4 << 3;
        int i7 = i2 + 1;
        if (i7 >= 100) {
            throw new zzgzh("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        while (k2.B() != Integer.MAX_VALUE && y(i7, k2, c2691uBB)) {
        }
        if ((i6 | 4) != k2.b) {
            throw new zzgzh("Protocol message end-group tag did not match expected tag.");
        }
        if (c2691uBB.e) {
            c2691uBB.e = false;
        }
        ((C2691uB) obj).c(i6 | 3, c2691uBB);
        return true;
    }

    @Override // com.google.android.gms.internal.ads.D
    public /* synthetic */ void a() {
    }

    @Override // com.google.android.gms.internal.ads.S1
    public void b(long j2) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2001eB
    public C2391nB c(Class cls) {
        if (!OA.class.isAssignableFrom(cls)) {
            throw new IllegalArgumentException("Unsupported message type: ".concat(cls.getName()));
        }
        try {
            return (C2391nB) OA.m(cls.asSubclass(OA.class)).s(3, null);
        } catch (Exception e2) {
            throw new RuntimeException("Unable to get message info for ".concat(cls.getName()), e2);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2001eB
    public boolean d(Class cls) {
        return OA.class.isAssignableFrom(cls);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0070  */
    @Override // com.google.android.gms.internal.ads.Z1
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int e(com.google.android.gms.internal.ads.C1832aG r4) {
        /*
            r3 = this;
            int r0 = r3.a
            switch(r0) {
                case 21: goto L7;
                default: goto L5;
            }
        L5:
            r4 = 1
            return r4
        L7:
            java.lang.String r4 = r4.m
            if (r4 == 0) goto L77
            int r0 = r4.hashCode()
            r1 = 1
            r2 = 2
            switch(r0) {
                case -1351681404: goto L66;
                case -1248334819: goto L5c;
                case -1026075066: goto L52;
                case -1004728940: goto L48;
                case 691401887: goto L3e;
                case 822864842: goto L34;
                case 1157994102: goto L2a;
                case 1668750253: goto L20;
                case 1693976202: goto L15;
                default: goto L14;
            }
        L14:
            goto L70
        L15:
            java.lang.String r0 = "application/ttml+xml"
            boolean r0 = r4.equals(r0)
            if (r0 == 0) goto L70
            r0 = 8
            goto L71
        L20:
            java.lang.String r0 = "application/x-subrip"
            boolean r0 = r4.equals(r0)
            if (r0 == 0) goto L70
            r0 = 3
            goto L71
        L2a:
            java.lang.String r0 = "application/vobsub"
            boolean r0 = r4.equals(r0)
            if (r0 == 0) goto L70
            r0 = 6
            goto L71
        L34:
            java.lang.String r0 = "text/x-ssa"
            boolean r0 = r4.equals(r0)
            if (r0 == 0) goto L70
            r0 = 0
            goto L71
        L3e:
            java.lang.String r0 = "application/x-quicktime-tx3g"
            boolean r0 = r4.equals(r0)
            if (r0 == 0) goto L70
            r0 = 4
            goto L71
        L48:
            java.lang.String r0 = "text/vtt"
            boolean r0 = r4.equals(r0)
            if (r0 == 0) goto L70
            r0 = r1
            goto L71
        L52:
            java.lang.String r0 = "application/x-mp4-vtt"
            boolean r0 = r4.equals(r0)
            if (r0 == 0) goto L70
            r0 = r2
            goto L71
        L5c:
            java.lang.String r0 = "application/pgs"
            boolean r0 = r4.equals(r0)
            if (r0 == 0) goto L70
            r0 = 5
            goto L71
        L66:
            java.lang.String r0 = "application/dvbsubs"
            boolean r0 = r4.equals(r0)
            if (r0 == 0) goto L70
            r0 = 7
            goto L71
        L70:
            r0 = -1
        L71:
            switch(r0) {
                case 0: goto L76;
                case 1: goto L76;
                case 2: goto L75;
                case 3: goto L76;
                case 4: goto L75;
                case 5: goto L75;
                case 6: goto L75;
                case 7: goto L75;
                case 8: goto L76;
                default: goto L74;
            }
        L74:
            goto L77
        L75:
            r1 = r2
        L76:
            return r1
        L77:
            java.lang.String r4 = java.lang.String.valueOf(r4)
            java.lang.IllegalArgumentException r0 = new java.lang.IllegalArgumentException
            java.lang.String r1 = "Unsupported MIME type: "
            java.lang.String r4 = r1.concat(r4)
            r0.<init>(r4)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1.e(com.google.android.gms.internal.ads.aG):int");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:38:0x007b  */
    @Override // com.google.android.gms.internal.ads.Z1
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.gms.internal.ads.InterfaceC1818a2 f(com.google.android.gms.internal.ads.C1832aG r15) throws java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 430
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1.f(com.google.android.gms.internal.ads.aG):com.google.android.gms.internal.ads.a2");
    }

    @Override // com.google.android.gms.internal.ads.Z1
    public boolean g(C1832aG c1832aG) {
        switch (this.a) {
            case 21:
                String str = c1832aG.m;
                return Objects.equals(str, "text/x-ssa") || Objects.equals(str, "text/vtt") || Objects.equals(str, "application/x-mp4-vtt") || Objects.equals(str, "application/x-subrip") || Objects.equals(str, "application/x-quicktime-tx3g") || Objects.equals(str, "application/pgs") || Objects.equals(str, "application/vobsub") || Objects.equals(str, "application/dvbsubs") || Objects.equals(str, "application/ttml+xml");
            default:
                return false;
        }
    }

    @Override // com.google.android.gms.internal.ads.K
    public long h(long j2) {
        return j2;
    }

    @Override // com.google.android.gms.internal.ads.S1
    public long j(P p) {
        return -1L;
    }

    @Override // com.google.android.gms.internal.ads.W
    public void n() {
        switch (this.a) {
            case 15:
                throw new UnsupportedOperationException();
            default:
                return;
        }
    }

    @Override // com.google.android.gms.internal.ads.W
    public void p(InterfaceC2122h0 interfaceC2122h0) {
        switch (this.a) {
            case 15:
                throw new UnsupportedOperationException();
            default:
                return;
        }
    }

    @Override // com.google.android.gms.internal.ads.W
    public InterfaceC2380n0 q(int i2, int i3) {
        switch (this.a) {
            case 15:
                throw new UnsupportedOperationException();
            default:
                return new T();
        }
    }

    @Override // com.google.android.gms.internal.ads.D
    /* renamed from: zza, reason: collision with other method in class */
    public /* synthetic */ void mo11zza() {
    }

    @Override // com.google.android.gms.internal.ads.S1
    public InterfaceC2122h0 zze() {
        return new Y(-9223372036854775807L, 0L);
    }

    public C1(C1 c1) {
        this.a = 24;
    }

    @Override // com.google.android.gms.internal.ads.Bt
    public Object zza() {
        int i2 = C2465p.a;
        try {
            return Class.forName("androidx.media3.effect.DefaultVideoFrameProcessor$Factory$Builder");
        } catch (Exception e2) {
            throw new IllegalStateException(e2);
        }
    }

    @Override // com.google.android.gms.internal.ads.Bt
    public Constructor zza() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        switch (this.a) {
            case 13:
                int[] iArr = S.c;
                if (Boolean.TRUE.equals(Class.forName("androidx.media3.decoder.flac.FlacLibrary").getMethod("isAvailable", null).invoke(null, null))) {
                    return Class.forName("androidx.media3.decoder.flac.FlacExtractor").asSubclass(U.class).getConstructor(Integer.TYPE);
                }
                return null;
            default:
                int[] iArr2 = S.c;
                return Class.forName("androidx.media3.decoder.midi.MidiExtractor").asSubclass(U.class).getConstructor(null);
        }
    }
}
