package com.google.android.gms.internal.ads;

import java.io.EOFException;

/* loaded from: classes2.dex */
public final class T implements InterfaceC2380n0 {
    public final byte[] a = new byte[4096];

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final void a(C1832aG c1832aG) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final void b(Kn kn, int i, int i2) {
        kn.k(i);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final int c(InterfaceC2779wD interfaceC2779wD, int i, boolean z) throws EOFException {
        int iD = interfaceC2779wD.d(0, this.a, Math.min(4096, i));
        if (iD != -1) {
            return iD;
        }
        if (z) {
            return -1;
        }
        throw new EOFException();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final int d(InterfaceC2779wD interfaceC2779wD, int i, boolean z) {
        return c(interfaceC2779wD, i, z);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final void e(int i, Kn kn) {
        kn.k(i);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final void f(long j, int i, int i2, int i3, C2337m0 c2337m0) {
    }
}
