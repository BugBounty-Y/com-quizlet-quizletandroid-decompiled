package com.google.android.gms.internal.ads;

import android.net.Uri;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.wz, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2807wz extends AbstractC2802wu implements InterfaceC2648tB {
    public final boolean e;
    public final int f;
    public final int g;
    public final String h;
    public final Fp i;
    public final Fp j;
    public C2891yx k;
    public HttpURLConnection l;
    public InputStream m;
    public boolean n;
    public int o;
    public long p;
    public long q;

    public /* synthetic */ C2807wz(String str, int i, int i2, boolean z, Fp fp) {
        super(true);
        this.h = str;
        this.f = i;
        this.g = i2;
        this.e = z;
        this.i = fp;
        this.j = new Fp(7);
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        HttpURLConnection httpURLConnection = this.l;
        if (httpURLConnection != null) {
            return Uri.parse(httpURLConnection.getURL().toString());
        }
        C2891yx c2891yx = this.k;
        if (c2891yx != null) {
            return c2891yx.a;
        }
        return null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0214  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x0235  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x016f  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0175  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0178  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x018b A[Catch: IOException -> 0x0196, TRY_LEAVE, TryCatch #1 {IOException -> 0x0196, blocks: (B:86:0x0183, B:88:0x018b), top: B:157:0x0183 }] */
    /* JADX WARN: Removed duplicated region for block: B:95:0x01a3  */
    /* JADX WARN: Type inference failed for: r6v11 */
    /* JADX WARN: Type inference failed for: r6v4, types: [java.lang.CharSequence, java.lang.String] */
    /* JADX WARN: Type inference failed for: r6v7 */
    /* JADX WARN: Type inference failed for: r6v8 */
    @Override // com.google.android.gms.internal.ads.Fw
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long c(com.google.android.gms.internal.ads.C2891yx r31) throws java.io.IOException, java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 672
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2807wz.c(com.google.android.gms.internal.ads.yx):long");
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x002b A[Catch: IOException -> 0x001e, TRY_LEAVE, TryCatch #0 {IOException -> 0x001e, blocks: (B:5:0x0004, B:7:0x000d, B:10:0x0017, B:13:0x0020, B:16:0x002b), top: B:20:0x0004 }] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int d(int r7, byte[] r8, int r9) throws java.io.IOException {
        /*
            r6 = this;
            if (r9 != 0) goto L4
            r7 = 0
            return r7
        L4:
            long r0 = r6.p     // Catch: java.io.IOException -> L1e
            r2 = -1
            int r2 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            r3 = -1
            if (r2 == 0) goto L20
            long r4 = r6.q     // Catch: java.io.IOException -> L1e
            long r0 = r0 - r4
            r4 = 0
            int r2 = (r0 > r4 ? 1 : (r0 == r4 ? 0 : -1))
            if (r2 != 0) goto L17
            goto L2a
        L17:
            long r4 = (long) r9     // Catch: java.io.IOException -> L1e
            long r0 = java.lang.Math.min(r4, r0)     // Catch: java.io.IOException -> L1e
            int r9 = (int) r0     // Catch: java.io.IOException -> L1e
            goto L20
        L1e:
            r7 = move-exception
            goto L35
        L20:
            java.io.InputStream r0 = r6.m     // Catch: java.io.IOException -> L1e
            java.lang.String r1 = com.google.android.gms.internal.ads.Yo.a     // Catch: java.io.IOException -> L1e
            int r7 = r0.read(r8, r7, r9)     // Catch: java.io.IOException -> L1e
            if (r7 != r3) goto L2b
        L2a:
            return r3
        L2b:
            long r8 = r6.q     // Catch: java.io.IOException -> L1e
            long r0 = (long) r7     // Catch: java.io.IOException -> L1e
            long r8 = r8 + r0
            r6.q = r8     // Catch: java.io.IOException -> L1e
            r6.e(r7)     // Catch: java.io.IOException -> L1e
            return r7
        L35:
            java.lang.String r8 = com.google.android.gms.internal.ads.Yo.a
            r8 = 2
            com.google.android.gms.internal.ads.zzgx r7 = com.google.android.gms.internal.ads.zzgx.a(r8, r7)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2807wz.d(int, byte[], int):int");
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.internal.ads.Fw
    public final void j() {
        try {
            InputStream inputStream = this.m;
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    String str = Yo.a;
                    throw new zzgx(e, 2000, 3);
                }
            }
        } finally {
            this.m = null;
            s();
            if (this.n) {
                this.n = false;
                b();
            }
            this.l = null;
            this.k = null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0069  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.net.HttpURLConnection q(java.net.URL r5, long r6, long r8, boolean r10, boolean r11, java.util.Map r12) throws java.io.IOException {
        /*
            r4 = this;
            java.net.URLConnection r5 = r5.openConnection()
            java.net.HttpURLConnection r5 = (java.net.HttpURLConnection) r5
            int r0 = r4.f
            r5.setConnectTimeout(r0)
            int r0 = r4.g
            r5.setReadTimeout(r0)
            java.util.HashMap r0 = new java.util.HashMap
            r0.<init>()
            com.google.android.gms.internal.ads.Fp r1 = r4.i
            java.util.Map r1 = r1.d()
            r0.putAll(r1)
            com.google.android.gms.internal.ads.Fp r1 = r4.j
            java.util.Map r1 = r1.d()
            r0.putAll(r1)
            r0.putAll(r12)
            java.util.Set r12 = r0.entrySet()
            java.util.Iterator r12 = r12.iterator()
        L32:
            boolean r0 = r12.hasNext()
            if (r0 == 0) goto L4e
            java.lang.Object r0 = r12.next()
            java.util.Map$Entry r0 = (java.util.Map.Entry) r0
            java.lang.Object r1 = r0.getKey()
            java.lang.String r1 = (java.lang.String) r1
            java.lang.Object r0 = r0.getValue()
            java.lang.String r0 = (java.lang.String) r0
            r5.setRequestProperty(r1, r0)
            goto L32
        L4e:
            r0 = 0
            int r12 = (r6 > r0 ? 1 : (r6 == r0 ? 0 : -1))
            r2 = -1
            if (r12 != 0) goto L5d
            int r6 = (r8 > r2 ? 1 : (r8 == r2 ? 0 : -1))
            if (r6 != 0) goto L5c
            r6 = 0
            goto L72
        L5c:
            r6 = r0
        L5d:
            java.lang.String r12 = "bytes="
            java.lang.String r0 = "-"
            java.lang.StringBuilder r12 = androidx.compose.animation.d0.t(r6, r12, r0)
            int r0 = (r8 > r2 ? 1 : (r8 == r2 ? 0 : -1))
            if (r0 == 0) goto L6e
            long r6 = r6 + r8
            long r6 = r6 + r2
            r12.append(r6)
        L6e:
            java.lang.String r6 = r12.toString()
        L72:
            if (r6 == 0) goto L79
            java.lang.String r7 = "Range"
            r5.setRequestProperty(r7, r6)
        L79:
            java.lang.String r6 = r4.h
            if (r6 == 0) goto L82
            java.lang.String r7 = "User-Agent"
            r5.setRequestProperty(r7, r6)
        L82:
            r6 = 1
            if (r6 == r10) goto L88
            java.lang.String r6 = "identity"
            goto L8a
        L88:
            java.lang.String r6 = "gzip"
        L8a:
            java.lang.String r7 = "Accept-Encoding"
            r5.setRequestProperty(r7, r6)
            r5.setInstanceFollowRedirects(r11)
            r6 = 0
            r5.setDoOutput(r6)
            int r6 = com.google.android.gms.internal.ads.C2891yx.f
            java.lang.String r6 = "GET"
            r5.setRequestMethod(r6)
            r5.connect()
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2807wz.q(java.net.URL, long, long, boolean, boolean, java.util.Map):java.net.HttpURLConnection");
    }

    public final URL r(URL url, String str) throws zzgx {
        if (str == null) {
            throw new zzgx("Null location redirect", com.pubmatic.sdk.common.h.AD_ALREADY_SHOWN, 1);
        }
        try {
            URL url2 = new URL(url, str);
            String protocol = url2.getProtocol();
            if (!"https".equals(protocol) && !"http".equals(protocol)) {
                throw new zzgx("Unsupported protocol redirect: ".concat(String.valueOf(protocol)), com.pubmatic.sdk.common.h.AD_ALREADY_SHOWN, 1);
            }
            if (this.e || protocol.equals(url.getProtocol())) {
                return url2;
            }
            throw new zzgx(AbstractC0147y.e("Disallowed cross-protocol redirect (", url.getProtocol(), " to ", protocol, ")"), com.pubmatic.sdk.common.h.AD_ALREADY_SHOWN, 1);
        } catch (MalformedURLException e) {
            throw new zzgx(e, com.pubmatic.sdk.common.h.AD_ALREADY_SHOWN, 1);
        }
    }

    public final void s() {
        HttpURLConnection httpURLConnection = this.l;
        if (httpURLConnection != null) {
            try {
                httpURLConnection.disconnect();
            } catch (Exception e) {
                AbstractC2096gb.A("DefaultHttpDataSource", "Unexpected error while disconnecting", e);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2802wu, com.google.android.gms.internal.ads.Fw
    public final Map zze() {
        HttpURLConnection httpURLConnection = this.l;
        return httpURLConnection == null ? Gu.g : new Ny(httpURLConnection.getHeaderFields());
    }
}
