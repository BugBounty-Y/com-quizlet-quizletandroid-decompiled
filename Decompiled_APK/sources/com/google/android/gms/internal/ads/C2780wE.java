package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;

/* renamed from: com.google.android.gms.internal.ads.wE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2780wE extends AbstractC1754Pf {
    public int i;
    public int j;
    public boolean k;
    public int l;
    public byte[] m;
    public int n;
    public long o;

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final void c(ByteBuffer byteBuffer) {
        int iPosition = byteBuffer.position();
        int iLimit = byteBuffer.limit();
        int i = iLimit - iPosition;
        if (i == 0) {
            return;
        }
        int iMin = Math.min(i, this.l);
        this.o += iMin / this.b.d;
        this.l -= iMin;
        byteBuffer.position(iPosition + iMin);
        if (this.l <= 0) {
            int i2 = i - iMin;
            int length = (this.n + i2) - this.m.length;
            ByteBuffer byteBufferE = e(length);
            int i3 = this.n;
            String str = Yo.a;
            int iMax = Math.max(0, Math.min(length, i3));
            byteBufferE.put(this.m, 0, iMax);
            int iMax2 = Math.max(0, Math.min(length - iMax, i2));
            byteBuffer.limit(byteBuffer.position() + iMax2);
            byteBufferE.put(byteBuffer);
            byteBuffer.limit(iLimit);
            int i4 = i2 - iMax2;
            int i5 = this.n - iMax;
            this.n = i5;
            byte[] bArr = this.m;
            System.arraycopy(bArr, iMax, bArr, 0, i5);
            byteBuffer.get(this.m, this.n, i4);
            this.n += i4;
            byteBufferE.flip();
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final C2229jf d(C2229jf c2229jf) throws zzcm {
        int i = c2229jf.c;
        if (i != 2 && i != 4) {
            throw new zzcm("Unhandled input format:", c2229jf);
        }
        this.k = true;
        return (this.i == 0 && this.j == 0) ? C2229jf.e : c2229jf;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf, com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final boolean g() {
        return super.g() && this.n == 0;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final void i() {
        if (this.k) {
            this.k = false;
            int i = this.j;
            int i2 = this.b.d;
            this.m = new byte[i * i2];
            this.l = this.i * i2;
        }
        this.n = 0;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final void k() {
        if (this.k) {
            if (this.n > 0) {
                this.o += r0 / this.b.d;
            }
            this.n = 0;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final void l() {
        this.m = Yo.b;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf, com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final ByteBuffer zzb() {
        int i;
        if (super.g() && (i = this.n) > 0) {
            e(i).put(this.m, 0, this.n).flip();
            this.n = 0;
        }
        return super.zzb();
    }
}
