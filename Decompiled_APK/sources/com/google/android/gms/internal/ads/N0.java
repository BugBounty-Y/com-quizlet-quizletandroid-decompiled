package com.google.android.gms.internal.ads;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class N0 implements InterfaceC2856y4 {
    public final int a;
    public final String b;
    public final String c;
    public final int d;
    public final int e;
    public final int f;
    public final int g;
    public final byte[] h;

    public N0(int i, String str, String str2, int i2, int i3, int i4, int i5, byte[] bArr) {
        this.a = i;
        this.b = str;
        this.c = str2;
        this.d = i2;
        this.e = i3;
        this.f = i4;
        this.g = i5;
        this.h = bArr;
    }

    public static N0 b(Kn kn) {
        int iU = kn.u();
        String strE = AbstractC2514q5.e(kn.b(kn.u(), StandardCharsets.US_ASCII));
        String strB = kn.b(kn.u(), StandardCharsets.UTF_8);
        int iU2 = kn.u();
        int iU3 = kn.u();
        int iU4 = kn.u();
        int iU5 = kn.u();
        int iU6 = kn.u();
        byte[] bArr = new byte[iU6];
        kn.f(0, bArr, iU6);
        return new N0(iU, strE, strB, iU2, iU3, iU4, iU5, bArr);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2856y4
    public final void a(L3 l3) {
        l3.a(this.a, this.h);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && N0.class == obj.getClass()) {
            N0 n0 = (N0) obj;
            if (this.a == n0.a && this.b.equals(n0.b) && this.c.equals(n0.c) && this.d == n0.d && this.e == n0.e && this.f == n0.f && this.g == n0.g && Arrays.equals(this.h, n0.h)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(this.h) + ((((((((((this.c.hashCode() + ((this.b.hashCode() + ((this.a + 527) * 31)) * 31)) * 31) + this.d) * 31) + this.e) * 31) + this.f) * 31) + this.g) * 31);
    }

    public final String toString() {
        return "Picture: mimeType=" + this.b + ", description=" + this.c;
    }
}
