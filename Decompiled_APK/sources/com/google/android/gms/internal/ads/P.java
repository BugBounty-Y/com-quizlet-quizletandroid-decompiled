package com.google.android.gms.internal.ads;

import java.io.EOFException;
import java.io.InterruptedIOException;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class P implements V {
    public final Fw b;
    public final long c;
    public long d;
    public int f;
    public int g;
    public byte[] e = new byte[65536];
    public final byte[] a = new byte[4096];

    static {
        E3.a("media3.extractor");
    }

    public P(Fw fw, long j, long j2) {
        this.b = fw;
        this.d = j;
        this.c = j2;
    }

    public final int b(int i, byte[] bArr, int i2) throws EOFException, InterruptedIOException {
        P p;
        int iMin;
        r(i2);
        int i3 = this.g;
        int i4 = this.f;
        int i5 = i3 - i4;
        if (i5 == 0) {
            p = this;
            iMin = p.q(this.e, i4, i2, 0, true);
            if (iMin == -1) {
                return -1;
            }
            p.g += iMin;
        } else {
            p = this;
            iMin = Math.min(i2, i5);
        }
        System.arraycopy(p.e, p.f, bArr, i, iMin);
        p.f += iMin;
        return iMin;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) throws EOFException, InterruptedIOException {
        P p;
        int i3 = this.g;
        int iQ = 0;
        if (i3 != 0) {
            int iMin = Math.min(i3, i2);
            System.arraycopy(this.e, 0, bArr, i, iMin);
            s(iMin);
            iQ = iMin;
        }
        if (iQ == 0) {
            p = this;
            iQ = p.q(bArr, i, i2, 0, true);
        } else {
            p = this;
        }
        if (iQ != -1) {
            p.d += iQ;
        }
        return iQ;
    }

    @Override // com.google.android.gms.internal.ads.V
    public final void e(int i) throws EOFException, InterruptedIOException {
        n(i, false);
    }

    @Override // com.google.android.gms.internal.ads.V
    public final long f() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.ads.V
    public final void g(int i) throws EOFException, InterruptedIOException {
        p(i);
    }

    @Override // com.google.android.gms.internal.ads.V
    public final boolean h(byte[] bArr, int i, int i2, boolean z) throws EOFException, InterruptedIOException {
        int iMin;
        int i3 = this.g;
        if (i3 == 0) {
            iMin = 0;
        } else {
            iMin = Math.min(i3, i2);
            System.arraycopy(this.e, 0, bArr, i, iMin);
            s(iMin);
        }
        int iQ = iMin;
        while (iQ < i2 && iQ != -1) {
            iQ = q(bArr, i, i2, iQ, z);
        }
        if (iQ != -1) {
            this.d += iQ;
        }
        return iQ != -1;
    }

    @Override // com.google.android.gms.internal.ads.V
    public final void i() {
        this.f = 0;
    }

    @Override // com.google.android.gms.internal.ads.V
    public final long j() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.ads.V
    public final boolean k(byte[] bArr, int i, int i2, boolean z) {
        if (!n(i2, z)) {
            return false;
        }
        System.arraycopy(this.e, this.f - i2, bArr, i, i2);
        return true;
    }

    @Override // com.google.android.gms.internal.ads.V
    public final void l(int i, byte[] bArr, int i2) {
        k(bArr, i, i2, false);
    }

    public final boolean n(int i, boolean z) throws EOFException, InterruptedIOException {
        r(i);
        int iQ = this.g - this.f;
        while (iQ < i) {
            int i2 = i;
            boolean z2 = z;
            iQ = q(this.e, this.f, i2, iQ, z2);
            if (iQ == -1) {
                return false;
            }
            this.g = this.f + iQ;
            i = i2;
            z = z2;
        }
        this.f += i;
        return true;
    }

    @Override // com.google.android.gms.internal.ads.V
    public final void o(int i, byte[] bArr, int i2) throws EOFException, InterruptedIOException {
        h(bArr, i, i2, false);
    }

    public final void p(int i) throws EOFException, InterruptedIOException {
        int iMin = Math.min(this.g, i);
        s(iMin);
        int iQ = iMin;
        while (iQ < i && iQ != -1) {
            iQ = q(this.a, -iQ, Math.min(i, iQ + 4096), iQ, false);
        }
        if (iQ != -1) {
            this.d += iQ;
        }
    }

    public final int q(byte[] bArr, int i, int i2, int i3, boolean z) throws EOFException, InterruptedIOException {
        if (Thread.interrupted()) {
            throw new InterruptedIOException();
        }
        int iD = this.b.d(i + i3, bArr, i2 - i3);
        if (iD != -1) {
            return i3 + iD;
        }
        if (i3 == 0 && z) {
            return -1;
        }
        throw new EOFException();
    }

    public final void r(int i) {
        int i2 = this.f + i;
        int length = this.e.length;
        if (i2 > length) {
            String str = Yo.a;
            this.e = Arrays.copyOf(this.e, Math.max(65536 + i2, Math.min(length + length, i2 + 524288)));
        }
    }

    public final void s(int i) {
        int i2 = this.g - i;
        this.g = i2;
        this.f = 0;
        byte[] bArr = this.e;
        byte[] bArr2 = i2 < bArr.length + (-524288) ? new byte[65536 + i2] : bArr;
        System.arraycopy(bArr, i, bArr2, 0, i2);
        this.e = bArr2;
    }

    @Override // com.google.android.gms.internal.ads.V
    public final long zze() {
        return this.d + this.f;
    }
}
