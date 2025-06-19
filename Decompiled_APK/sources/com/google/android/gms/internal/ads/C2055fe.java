package com.google.android.gms.internal.ads;

import android.net.Uri;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.fe, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2055fe implements Fw {
    public final C1898bv a;
    public final long b;
    public final Fw c;
    public long d;
    public Uri e;

    public C2055fe(C1898bv c1898bv, int i, Fw fw) {
        this.a = c1898bv;
        this.b = i;
        this.c = fw;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final long c(C2891yx c2891yx) {
        C2891yx c2891yx2;
        C2891yx c2891yx3;
        C2891yx c2891yx4;
        Uri uri = c2891yx.a;
        this.e = uri;
        long j = c2891yx.c;
        long j2 = this.b;
        long j3 = c2891yx.d;
        if (j >= j2) {
            c2891yx2 = null;
        } else {
            long jMin = j2 - j;
            if (j3 != -1) {
                jMin = Math.min(j3, jMin);
            }
            c2891yx2 = new C2891yx(uri, j, jMin);
        }
        if (j3 == -1 || j + j3 > j2) {
            c2891yx3 = c2891yx2;
            c2891yx4 = new C2891yx(uri, Math.max(j2, j), j3 != -1 ? Math.min(j3, (j + j3) - j2) : -1L);
        } else {
            c2891yx3 = c2891yx2;
            c2891yx4 = null;
        }
        long jC = c2891yx3 != null ? this.a.c(c2891yx3) : 0L;
        long jC2 = c2891yx4 != null ? this.c.c(c2891yx4) : 0L;
        this.d = j;
        if (jC == -1 || jC2 == -1) {
            return -1L;
        }
        return jC + jC2;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) {
        int i3;
        long j = this.d;
        long j2 = this.b;
        if (j < j2) {
            int iD = this.a.d(i, bArr, (int) Math.min(i2, j2 - j));
            long j3 = this.d + iD;
            this.d = j3;
            i3 = iD;
            j = j3;
        } else {
            i3 = 0;
        }
        if (j < j2) {
            return i3;
        }
        int iD2 = this.c.d(i + i3, bArr, i2 - i3);
        int i4 = i3 + iD2;
        this.d += iD2;
        return i4;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void j() {
        this.a.j();
        this.c.j();
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void m(FC fc) {
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Map zze() {
        return Gu.g;
    }
}
