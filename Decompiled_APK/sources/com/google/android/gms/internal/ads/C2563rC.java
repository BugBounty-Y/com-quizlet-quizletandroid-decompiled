package com.google.android.gms.internal.ads;

import android.net.Uri;
import java.util.Collections;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.rC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2563rC implements Fw {
    public final Fw a;
    public Uri b = Uri.EMPTY;

    public C2563rC(Fw fw) {
        this.a = fw;
        Map map = Collections.EMPTY_MAP;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        return this.a.a();
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final long c(C2891yx c2891yx) {
        Fw fw = this.a;
        this.b = c2891yx.a;
        Map map = Collections.EMPTY_MAP;
        try {
            long jC = fw.c(c2891yx);
            Uri uriA = fw.a();
            if (uriA != null) {
                this.b = uriA;
            }
            fw.zze();
            return jC;
        } catch (Throwable th) {
            Uri uriA2 = fw.a();
            if (uriA2 != null) {
                this.b = uriA2;
            }
            fw.zze();
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) {
        return this.a.d(i, bArr, i2);
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void j() {
        this.a.j();
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void m(FC fc) {
        fc.getClass();
        this.a.m(fc);
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Map zze() {
        return this.a.zze();
    }
}
