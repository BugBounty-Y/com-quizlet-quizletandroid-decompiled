package com.google.android.gms.internal.ads;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class O1 extends U1 {
    public Z n;
    public androidx.compose.foundation.lazy.layout.p0 o;

    @Override // com.google.android.gms.internal.ads.U1
    public final long a(Kn kn) {
        byte[] bArr = kn.a;
        if (bArr[0] != -1) {
            return -1L;
        }
        int i = (bArr[2] & 255) >> 4;
        if (i == 6) {
            kn.k(4);
            kn.J();
        } else if (i == 7) {
            i = 7;
            kn.k(4);
            kn.J();
        }
        int iC = AbstractC1795We.c(i, kn);
        kn.j(0);
        return iC;
    }

    @Override // com.google.android.gms.internal.ads.U1
    public final void b(boolean z) {
        super.b(z);
        if (z) {
            this.n = null;
            this.o = null;
        }
    }

    @Override // com.google.android.gms.internal.ads.U1
    public final boolean c(Kn kn, long j, Fi fi) {
        byte[] bArr = kn.a;
        Z z = this.n;
        if (z == null) {
            Z z2 = new Z(17, bArr);
            this.n = z2;
            EF ef = new EF(z2.b(Arrays.copyOfRange(bArr, 9, kn.c), null));
            ef.a("audio/ogg");
            fi.b = new C1832aG(ef);
            return true;
        }
        byte b = bArr[0];
        if ((b & Byte.MAX_VALUE) != 3) {
            if (b != -1) {
                return true;
            }
            androidx.compose.foundation.lazy.layout.p0 p0Var = this.o;
            if (p0Var != null) {
                p0Var.a = j;
                fi.c = p0Var;
            }
            ((C1832aG) fi.b).getClass();
            return false;
        }
        Fi fiM = AbstractC1972di.m(kn);
        Z z3 = new Z(z.a, z.b, z.c, z.d, z.e, z.g, z.h, z.j, fiM, z.l);
        this.n = z3;
        androidx.compose.foundation.lazy.layout.p0 p0Var2 = new androidx.compose.foundation.lazy.layout.p0();
        p0Var2.c = z3;
        p0Var2.d = fiM;
        p0Var2.a = -1L;
        p0Var2.b = -1L;
        this.o = p0Var2;
        return true;
    }
}
