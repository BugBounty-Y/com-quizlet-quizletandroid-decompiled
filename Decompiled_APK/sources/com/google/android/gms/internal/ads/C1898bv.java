package com.google.android.gms.internal.ads;

import android.net.Uri;

/* renamed from: com.google.android.gms.internal.ads.bv, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1898bv extends AbstractC2802wu {
    public Uri e;
    public byte[] f;
    public int g;
    public int h;
    public boolean i;
    public final C2586rt j;

    public C1898bv(byte[] bArr) {
        C2586rt c2586rt = new C2586rt(bArr, 1);
        super(false);
        this.j = c2586rt;
        AbstractC1795We.B(bArr.length > 0);
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final long c(C2891yx c2891yx) throws zzgh {
        n(c2891yx);
        this.e = c2891yx.a;
        byte[] bArr = (byte[]) this.j.b;
        this.f = bArr;
        int length = bArr.length;
        long j = length;
        long j2 = c2891yx.c;
        if (j2 > j) {
            throw new zzgh();
        }
        int i = (int) j2;
        this.g = i;
        int i2 = length - i;
        this.h = i2;
        long j3 = c2891yx.d;
        if (j3 != -1) {
            this.h = (int) Math.min(i2, j3);
        }
        this.i = true;
        p(c2891yx);
        return j3 != -1 ? j3 : this.h;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) {
        if (i2 == 0) {
            return 0;
        }
        int i3 = this.h;
        if (i3 == 0) {
            return -1;
        }
        int iMin = Math.min(i2, i3);
        byte[] bArr2 = this.f;
        AbstractC1795We.p(bArr2);
        System.arraycopy(bArr2, this.g, bArr, i, iMin);
        this.g += iMin;
        this.h -= iMin;
        e(iMin);
        return iMin;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void j() {
        if (this.i) {
            this.i = false;
            b();
        }
        this.e = null;
        this.f = null;
    }
}
