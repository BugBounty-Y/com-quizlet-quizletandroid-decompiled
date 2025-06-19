package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;

/* renamed from: com.google.android.gms.internal.ads.g3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2081g3 implements InterfaceC2211j3 {
    public final InterfaceC2037f3 a;
    public final Kn b = new Kn(32);
    public int c;
    public int d;
    public boolean e;
    public boolean f;

    public C2081g3(InterfaceC2037f3 interfaceC2037f3) {
        this.a = interfaceC2037f3;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2211j3
    public final void a() {
        this.f = true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2211j3
    public final void b(int i, Kn kn) {
        int i2 = i & 1;
        int iZ = i2 != 0 ? kn.b + kn.z() : -1;
        if (this.f) {
            if (i2 == 0) {
                return;
            }
            this.f = false;
            kn.j(iZ);
            this.d = 0;
        }
        while (kn.s() > 0) {
            int i3 = this.d;
            Kn kn2 = this.b;
            if (i3 < 3) {
                if (i3 == 0) {
                    int iZ2 = kn.z();
                    kn.j(kn.b - 1);
                    if (iZ2 == 255) {
                        this.f = true;
                        return;
                    }
                }
                int iMin = Math.min(kn.s(), 3 - this.d);
                kn.f(this.d, kn2.a, iMin);
                int i4 = this.d + iMin;
                this.d = i4;
                if (i4 == 3) {
                    kn2.j(0);
                    kn2.i(3);
                    kn2.k(1);
                    int iZ3 = kn2.z();
                    boolean z = (iZ3 & 128) != 0;
                    int iZ4 = kn2.z();
                    this.e = z;
                    int i5 = (((iZ3 & 15) << 8) | iZ4) + 3;
                    this.c = i5;
                    byte[] bArr = kn2.a;
                    if (bArr.length < i5) {
                        int length = bArr.length;
                        kn2.e(Math.min(4098, Math.max(i5, length + length)));
                    }
                }
            } else {
                int iMin2 = Math.min(kn.s(), this.c - this.d);
                kn.f(this.d, kn2.a, iMin2);
                int i6 = this.d + iMin2;
                this.d = i6;
                int i7 = this.c;
                if (i6 != i7) {
                    continue;
                } else {
                    if (!this.e) {
                        kn2.i(i7);
                    } else {
                        if (Yo.l(0, i7, kn2.a, -1) != 0) {
                            this.f = true;
                            return;
                        }
                        kn2.i(this.c - 4);
                    }
                    kn2.j(0);
                    this.a.d(kn2);
                    this.d = 0;
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2211j3
    public final void e(Eo eo, W w, C0591b1 c0591b1) {
        this.a.e(eo, w, c0591b1);
        this.f = true;
    }
}
