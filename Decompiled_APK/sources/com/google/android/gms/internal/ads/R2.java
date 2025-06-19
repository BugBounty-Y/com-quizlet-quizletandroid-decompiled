package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class R2 {
    public final InterfaceC2380n0 a;
    public boolean b;
    public boolean c;
    public boolean d;
    public int e;
    public int f;
    public long g;
    public long h;

    public R2(InterfaceC2380n0 interfaceC2380n0) {
        this.a = interfaceC2380n0;
    }

    public final void a(int i, byte[] bArr, int i2) {
        if (this.c) {
            int i3 = this.f;
            int i4 = (i + 1) - i3;
            if (i4 >= i2) {
                this.f = (i2 - i) + i3;
            } else {
                this.d = ((bArr[i4] & 192) >> 6) == 0;
                this.c = false;
            }
        }
    }

    public final void b(boolean z, long j, int i) {
        AbstractC1795We.L(this.h != -9223372036854775807L);
        if (this.e == 182 && z && this.b) {
            long j2 = j - this.g;
            this.a.f(this.h, this.d ? 1 : 0, (int) j2, i, null);
        }
        if (this.e != 179) {
            this.g = j;
        }
    }
}
