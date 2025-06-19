package com.google.android.gms.internal.ads;

import android.net.Uri;
import java.util.Map;

/* loaded from: classes2.dex */
public final class XE implements Fw {
    public final Fw a;
    public final int b;
    public final C2566rF c;
    public final byte[] d;
    public int e;

    public XE(Fw fw, int i, C2566rF c2566rF) {
        AbstractC1795We.B(i > 0);
        this.a = fw;
        this.b = i;
        this.c = c2566rF;
        this.d = new byte[1];
        this.e = i;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        return this.a.a();
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final long c(C2891yx c2891yx) {
        throw new UnsupportedOperationException();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) {
        int i3 = this.e;
        Fw fw = this.a;
        if (i3 == 0) {
            byte[] bArr2 = this.d;
            int i4 = 0;
            if (fw.d(0, bArr2, 1) != -1) {
                int i5 = (bArr2[0] & 255) << 4;
                if (i5 != 0) {
                    byte[] bArr3 = new byte[i5];
                    int i6 = i5;
                    while (i6 > 0) {
                        int iD = fw.d(i4, bArr3, i6);
                        if (iD != -1) {
                            i4 += iD;
                            i6 -= iD;
                        }
                    }
                    while (i5 > 0) {
                        int i7 = i5 - 1;
                        if (bArr3[i7] != 0) {
                            break;
                        }
                        i5 = i7;
                    }
                    if (i5 > 0) {
                        Kn kn = new Kn(i5, bArr3);
                        C2566rF c2566rF = this.c;
                        long jMax = !c2566rF.l ? c2566rF.i : Math.max(c2566rF.m.t(true), c2566rF.i);
                        int iS = kn.s();
                        InterfaceC2380n0 interfaceC2380n0 = c2566rF.k;
                        interfaceC2380n0.getClass();
                        interfaceC2380n0.e(iS, kn);
                        interfaceC2380n0.f(jMax, 1, iS, 0, null);
                        c2566rF.l = true;
                    }
                }
                i3 = this.b;
                this.e = i3;
            }
            return -1;
        }
        int iD2 = fw.d(i, bArr, Math.min(i3, i2));
        if (iD2 != -1) {
            this.e -= iD2;
        }
        return iD2;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void j() {
        throw new UnsupportedOperationException();
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void m(FC fc) {
        fc.getClass();
        this.a.m(fc);
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Map zze() {
        return this.a.zze();
    }
}
