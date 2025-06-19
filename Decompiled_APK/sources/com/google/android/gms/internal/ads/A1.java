package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class A1 {
    public final InterfaceC2380n0 a;
    public L1 d;
    public C2810x1 e;
    public int f;
    public int g;
    public int h;
    public int i;
    public final String j;
    public boolean m;
    public final K1 b = new K1();
    public final Kn c = new Kn();
    public final Kn k = new Kn(1);
    public final Kn l = new Kn();

    public A1(InterfaceC2380n0 interfaceC2380n0, L1 l1, C2810x1 c2810x1, String str) {
        this.a = interfaceC2380n0;
        this.d = l1;
        this.e = c2810x1;
        this.j = str;
        d(l1, c2810x1);
    }

    public final int a() {
        int i = !this.m ? this.d.g[this.f] : this.b.j[this.f] ? 1 : 0;
        return c() != null ? i | 1073741824 : i;
    }

    public final int b(int i, int i2) {
        Kn kn;
        J1 j1C = c();
        if (j1C == null) {
            return 0;
        }
        K1 k1 = this.b;
        int length = j1C.d;
        if (length != 0) {
            kn = k1.n;
        } else {
            String str = Yo.a;
            byte[] bArr = j1C.e;
            length = bArr.length;
            Kn kn2 = this.l;
            kn2.h(length, bArr);
            kn = kn2;
        }
        boolean z = k1.k && k1.l[this.f];
        boolean z2 = z || i2 != 0;
        int i3 = true != z2 ? 0 : 128;
        Kn kn3 = this.k;
        kn3.a[0] = (byte) (i3 | length);
        kn3.j(0);
        InterfaceC2380n0 interfaceC2380n0 = this.a;
        interfaceC2380n0.b(kn3, 1, 1);
        interfaceC2380n0.b(kn, length, 1);
        if (!z2) {
            return length + 1;
        }
        Kn kn4 = this.c;
        if (!z) {
            kn4.g(8);
            byte[] bArr2 = kn4.a;
            bArr2[0] = 0;
            bArr2[1] = 1;
            bArr2[2] = 0;
            bArr2[3] = (byte) i2;
            bArr2[4] = (byte) ((i >> 24) & 255);
            bArr2[5] = (byte) ((i >> 16) & 255);
            bArr2[6] = (byte) ((i >> 8) & 255);
            bArr2[7] = (byte) (i & 255);
            interfaceC2380n0.b(kn4, 8, 1);
            return length + 9;
        }
        int i4 = length + 1;
        Kn kn5 = k1.n;
        int iD = kn5.D();
        kn5.k(-2);
        int i5 = (iD * 6) + 2;
        if (i2 != 0) {
            kn4.g(i5);
            byte[] bArr3 = kn4.a;
            kn5.f(0, bArr3, i5);
            int i6 = (((bArr3[2] & 255) << 8) | (bArr3[3] & 255)) + i2;
            bArr3[2] = (byte) ((i6 >> 8) & 255);
            bArr3[3] = (byte) (i6 & 255);
        } else {
            kn4 = kn5;
        }
        interfaceC2380n0.b(kn4, i5, 1);
        return i4 + i5;
    }

    public final J1 c() {
        if (!this.m) {
            return null;
        }
        K1 k1 = this.b;
        C2810x1 c2810x1 = k1.a;
        String str = Yo.a;
        int i = c2810x1.a;
        J1 j1 = k1.m;
        if (j1 == null) {
            j1 = this.d.a.l[i];
        }
        if (j1 == null || !j1.a) {
            return null;
        }
        return j1;
    }

    public final void d(L1 l1, C2810x1 c2810x1) {
        this.d = l1;
        this.e = c2810x1;
        EF ef = new EF(l1.a.g);
        ef.a(this.j);
        this.a.a(new C1832aG(ef));
        e();
    }

    public final void e() {
        K1 k1 = this.b;
        k1.d = 0;
        k1.p = 0L;
        k1.q = false;
        k1.k = false;
        k1.o = false;
        k1.m = null;
        this.f = 0;
        this.h = 0;
        this.g = 0;
        this.i = 0;
        this.m = false;
    }

    public final boolean f() {
        this.f++;
        if (!this.m) {
            return false;
        }
        int i = this.g + 1;
        this.g = i;
        int[] iArr = this.b.g;
        int i2 = this.h;
        if (i != iArr[i2]) {
            return true;
        }
        this.h = i2 + 1;
        this.g = 0;
        return false;
    }
}
