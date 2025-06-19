package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.o0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2423o0 {
    public final byte[] a = new byte[10];
    public boolean b;
    public int c;
    public long d;
    public int e;
    public int f;
    public int g;

    public final void a(InterfaceC2380n0 interfaceC2380n0, C2337m0 c2337m0) {
        if (this.c > 0) {
            interfaceC2380n0.f(this.d, this.e, this.f, this.g, c2337m0);
            this.c = 0;
        }
    }

    public final void b(InterfaceC2380n0 interfaceC2380n0, long j, int i, int i2, int i3, C2337m0 c2337m0) {
        if (!(this.g <= i2 + i3)) {
            throw new IllegalStateException("TrueHD chunk samples must be contiguous in the sample queue.");
        }
        if (this.b) {
            int i4 = this.c;
            int i5 = i4 + 1;
            this.c = i5;
            if (i4 == 0) {
                this.d = j;
                this.e = i;
                this.f = 0;
            }
            this.f += i2;
            this.g = i3;
            if (i5 >= 16) {
                a(interfaceC2380n0, c2337m0);
            }
        }
    }

    public final void c(V v) {
        if (this.b) {
            return;
        }
        byte[] bArr = this.a;
        v.l(0, bArr, 10);
        v.i();
        if (bArr[4] == -8 && bArr[5] == 114 && bArr[6] == 111 && (bArr[7] & 254) == 186) {
            this.b = true;
        }
    }
}
