package com.google.android.gms.internal.ads;

import androidx.camera.core.impl.C0186z;
import java.io.EOFException;

/* renamed from: com.google.android.gms.internal.ads.b2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1862b2 implements InterfaceC2380n0 {
    public final InterfaceC2380n0 a;
    public final Z1 b;
    public InterfaceC1818a2 g;
    public C1832aG h;
    public boolean i;
    public int d = 0;
    public int e = 0;
    public byte[] f = Yo.b;
    public final Kn c = new Kn();

    public C1862b2(InterfaceC2380n0 interfaceC2380n0, Z1 z1) {
        this.a = interfaceC2380n0;
        this.b = z1;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final void a(C1832aG c1832aG) {
        String str = c1832aG.m;
        str.getClass();
        AbstractC1795We.B(AbstractC2514q5.b(str) == 3);
        boolean zEquals = c1832aG.equals(this.h);
        Z1 z1 = this.b;
        if (!zEquals) {
            this.h = c1832aG;
            this.g = z1.g(c1832aG) ? z1.f(c1832aG) : null;
        }
        InterfaceC1818a2 interfaceC1818a2 = this.g;
        InterfaceC2380n0 interfaceC2380n0 = this.a;
        if (interfaceC1818a2 == null) {
            interfaceC2380n0.a(c1832aG);
            return;
        }
        EF ef = new EF(c1832aG);
        ef.d("application/x-media3-cues");
        ef.i = str;
        ef.q = Long.MAX_VALUE;
        ef.H = z1.e(c1832aG);
        interfaceC2380n0.a(new C1832aG(ef));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final void b(Kn kn, int i, int i2) {
        if (this.g == null) {
            this.a.b(kn, i, i2);
            return;
        }
        g(i);
        kn.f(this.e, this.f, i);
        this.e += i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final int c(InterfaceC2779wD interfaceC2779wD, int i, boolean z) throws EOFException {
        if (this.g == null) {
            return this.a.c(interfaceC2779wD, i, z);
        }
        g(i);
        int iD = interfaceC2779wD.d(this.e, this.f, i);
        if (iD != -1) {
            this.e += iD;
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
        b(kn, i, 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final void f(long j, int i, int i2, int i3, C2337m0 c2337m0) {
        if (this.g == null) {
            this.a.f(j, i, i2, i3, c2337m0);
            return;
        }
        AbstractC1795We.G(c2337m0 == null, "DRM on subtitles is not supported");
        int i4 = (this.e - i3) - i2;
        try {
            this.g.a(this.f, i4, i2, new C0186z(this, j, i));
        } catch (RuntimeException e) {
            if (!this.i) {
                throw e;
            }
            AbstractC2096gb.M("SubtitleTranscodingTO", "Parsing subtitles failed, ignoring sample.", e);
        }
        int i5 = i4 + i2;
        this.d = i5;
        if (i5 == this.e) {
            this.d = 0;
            this.e = 0;
        }
    }

    public final void g(int i) {
        int length = this.f.length;
        int i2 = this.e;
        if (length - i2 >= i) {
            return;
        }
        int i3 = i2 - this.d;
        int iMax = Math.max(i3 + i3, i + i3);
        byte[] bArr = this.f;
        byte[] bArr2 = iMax <= bArr.length ? bArr : new byte[iMax];
        System.arraycopy(bArr, this.d, bArr2, 0, i3);
        this.d = 0;
        this.e = i3;
        this.f = bArr2;
    }
}
