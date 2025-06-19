package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class T1 extends U1 {
    public static final byte[] o = {79, 112, 117, 115, 72, 101, 97, 100};
    public static final byte[] p = {79, 112, 117, 115, 84, 97, 103, 115};
    public boolean n;

    public static boolean e(Kn kn, byte[] bArr) {
        if (kn.s() < 8) {
            return false;
        }
        int i = kn.b;
        byte[] bArr2 = new byte[8];
        kn.f(0, bArr2, 8);
        kn.j(i);
        return Arrays.equals(bArr2, bArr);
    }

    @Override // com.google.android.gms.internal.ads.U1
    public final long a(Kn kn) {
        byte[] bArr = kn.a;
        return (this.i * LA.C(bArr[0], bArr.length > 1 ? bArr[1] : (byte) 0)) / 1000000;
    }

    @Override // com.google.android.gms.internal.ads.U1
    public final void b(boolean z) {
        super.b(z);
        if (z) {
            this.n = false;
        }
    }

    @Override // com.google.android.gms.internal.ads.U1
    public final boolean c(Kn kn, long j, Fi fi) {
        if (e(kn, o)) {
            byte[] bArrCopyOf = Arrays.copyOf(kn.a, kn.c);
            int i = bArrCopyOf[9] & 255;
            ArrayList arrayListA = LA.A(bArrCopyOf);
            if (((C1832aG) fi.b) == null) {
                EF ef = new EF();
                ef.a("audio/ogg");
                ef.d("audio/opus");
                ef.B = i;
                ef.C = 48000;
                ef.o = arrayListA;
                fi.b = new C1832aG(ef);
                return true;
            }
        } else {
            if (!e(kn, p)) {
                AbstractC1795We.p((C1832aG) fi.b);
                return false;
            }
            AbstractC1795We.p((C1832aG) fi.b);
            if (!this.n) {
                this.n = true;
                kn.k(8);
                K4 k4M = AbstractC2096gb.m(AbstractC2330lu.o((String[]) AbstractC2096gb.r(kn, false, false).b));
                if (k4M != null) {
                    C1832aG c1832aG = (C1832aG) fi.b;
                    c1832aG.getClass();
                    EF ef2 = new EF(c1832aG);
                    ef2.j = k4M.b(((C1832aG) fi.b).k);
                    fi.b = new C1832aG(ef2);
                }
            }
        }
        return true;
    }
}
