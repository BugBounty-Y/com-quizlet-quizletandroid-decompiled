package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.HandlerThread;
import android.text.TextUtils;
import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import javax.crypto.Mac;

/* loaded from: classes2.dex */
public final class As implements My, InterfaceC2491pj {
    public int a;
    public final Object b;
    public Object c;
    public Object d;

    public As() {
        this.b = new Object();
        this.c = null;
        this.d = null;
        this.a = 0;
    }

    @Override // com.google.android.gms.internal.ads.My
    public byte[] a(int i, byte[] bArr) throws IllegalStateException, InvalidAlgorithmParameterException {
        if (i > this.a) {
            throw new InvalidAlgorithmParameterException("tag size too big");
        }
        C2519qA c2519qA = (C2519qA) this.b;
        ((Mac) c2519qA.get()).update(bArr);
        return Arrays.copyOf(((Mac) c2519qA.get()).doFinal(), i);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2491pj, com.google.android.gms.internal.ads.Pk
    /* renamed from: b */
    public void mo10b(Object obj) {
        ((InterfaceC2266kF) obj).d(0, ((C2866yE) this.b).a, (YE) this.c, (androidx.compose.animation.core.S0) this.d, this.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x006e, code lost:
    
        if (r10 == false) goto L56;
     */
    /* JADX WARN: Removed duplicated region for block: B:25:0x007f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean c(com.google.android.gms.internal.ads.C2642t5 r9, com.google.android.gms.internal.ads.C1 r10) {
        /*
            Method dump skipped, instructions count: 441
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.As.c(com.google.android.gms.internal.ads.t5, com.google.android.gms.internal.ads.C1):boolean");
    }

    public C2728v5 d(int i) {
        String string;
        int i2 = this.a;
        SharedPreferences sharedPreferences = (SharedPreferences) this.d;
        if (i == 1) {
            StringBuilder sb = new StringBuilder("LATMTD");
            sb.append(i2 - 1);
            string = sharedPreferences.getString(sb.toString(), null);
        } else {
            StringBuilder sb2 = new StringBuilder("FBAMTD");
            sb2.append(i2 - 1);
            string = sharedPreferences.getString(sb2.toString(), null);
        }
        if (!TextUtils.isEmpty(string)) {
            try {
                byte[] bArrN = com.google.android.gms.common.util.c.n(string);
                C2728v5 c2728v5B = C2728v5.B(BA.w(0, bArrN, bArrN.length));
                String strE = c2728v5B.E();
                File fileQ = AbstractC2025es.q(strE, "pcam.jar", f());
                if (!fileQ.exists()) {
                    fileQ = AbstractC2025es.q(strE, "pcam", f());
                }
                File fileQ2 = AbstractC2025es.q(strE, "pcbc", f());
                if (fileQ.exists()) {
                    if (fileQ2.exists()) {
                        return c2728v5B;
                    }
                }
            } catch (zzgzh unused) {
            }
        }
        return null;
    }

    public void e() {
        HandlerThread handlerThread;
        synchronized (this.b) {
            try {
                AbstractC1795We.L(this.a > 0);
                int i = this.a - 1;
                this.a = i;
                if (i == 0 && (handlerThread = (HandlerThread) this.d) != null) {
                    handlerThread.quit();
                    this.d = null;
                    this.c = null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public File f() {
        File file = new File((File) this.b, Integer.toString(this.a - 1));
        if (!file.exists()) {
            file.mkdir();
        }
        return file;
    }

    public As(InterfaceC2589rw interfaceC2589rw, C2883yp c2883yp) {
        TD td = new TD(20);
        this.b = interfaceC2589rw;
        this.c = c2883yp;
        this.d = td;
        this.a = 1048576;
    }

    public /* synthetic */ As(C2866yE c2866yE, YE ye, androidx.compose.animation.core.S0 s0, int i) {
        this.b = c2866yE;
        this.c = ye;
        this.d = s0;
        this.a = i;
    }

    public As(Context context, int i) {
        this.d = context.getSharedPreferences("pcvmspf", 0);
        File dir = context.getDir("pccache", 0);
        AbstractC2025es.l(dir, false);
        this.b = dir;
        File dir2 = context.getDir("tmppccache", 0);
        AbstractC2025es.l(dir2, true);
        this.c = dir2;
        this.a = i;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:24:0x005b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public As(java.lang.String r6, javax.crypto.spec.SecretKeySpec r7) throws java.security.GeneralSecurityException {
        /*
            r5 = this;
            r5.<init>()
            com.google.android.gms.internal.ads.qA r0 = new com.google.android.gms.internal.ads.qA
            r0.<init>(r5)
            r5.b = r0
            r1 = 2
            boolean r2 = com.google.android.gms.internal.ads.AbstractC1981ds.j(r1)
            if (r2 == 0) goto L8e
            r5.c = r6
            r5.d = r7
            byte[] r7 = r7.getEncoded()
            int r7 = r7.length
            r2 = 16
            if (r7 < r2) goto L86
            int r7 = r6.hashCode()
            r2 = 1
            r3 = 3
            r4 = 4
            switch(r7) {
                case -1823053428: goto L51;
                case 392315023: goto L47;
                case 392315118: goto L3d;
                case 392316170: goto L33;
                case 392317873: goto L29;
                default: goto L28;
            }
        L28:
            goto L5b
        L29:
            java.lang.String r7 = "HMACSHA512"
            boolean r7 = r6.equals(r7)
            if (r7 == 0) goto L5b
            r7 = r4
            goto L5c
        L33:
            java.lang.String r7 = "HMACSHA384"
            boolean r7 = r6.equals(r7)
            if (r7 == 0) goto L5b
            r7 = r3
            goto L5c
        L3d:
            java.lang.String r7 = "HMACSHA256"
            boolean r7 = r6.equals(r7)
            if (r7 == 0) goto L5b
            r7 = r1
            goto L5c
        L47:
            java.lang.String r7 = "HMACSHA224"
            boolean r7 = r6.equals(r7)
            if (r7 == 0) goto L5b
            r7 = r2
            goto L5c
        L51:
            java.lang.String r7 = "HMACSHA1"
            boolean r7 = r6.equals(r7)
            if (r7 == 0) goto L5b
            r7 = 0
            goto L5c
        L5b:
            r7 = -1
        L5c:
            if (r7 == 0) goto L7e
            if (r7 == r2) goto L7b
            if (r7 == r1) goto L78
            if (r7 == r3) goto L75
            if (r7 != r4) goto L69
            r6 = 64
            goto L80
        L69:
            java.lang.String r7 = "unknown Hmac algorithm: "
            java.lang.String r6 = r7.concat(r6)
            java.security.NoSuchAlgorithmException r7 = new java.security.NoSuchAlgorithmException
            r7.<init>(r6)
            throw r7
        L75:
            r6 = 48
            goto L80
        L78:
            r6 = 32
            goto L80
        L7b:
            r6 = 28
            goto L80
        L7e:
            r6 = 20
        L80:
            r5.a = r6
            r0.get()
            return
        L86:
            java.security.InvalidAlgorithmParameterException r6 = new java.security.InvalidAlgorithmParameterException
            java.lang.String r7 = "key size too small, need at least 16 bytes"
            r6.<init>(r7)
            throw r6
        L8e:
            java.security.GeneralSecurityException r6 = new java.security.GeneralSecurityException
            java.lang.String r7 = "Can not use HMAC in FIPS-mode, as BoringCrypto module is not available."
            r6.<init>(r7)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.As.<init>(java.lang.String, javax.crypto.spec.SecretKeySpec):void");
    }
}
