package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;

/* loaded from: classes2.dex */
public final class I2 implements N2 {
    public final /* synthetic */ int a;
    public final C2466p0 b;
    public final Kn c;
    public final String d;
    public final int e;
    public final String f;
    public String g;
    public InterfaceC2380n0 h;
    public int i;
    public int j;
    public boolean k;
    public long l;
    public C1832aG m;
    public int n;
    public long o;

    public I2(String str, int i, String str2, int i2) {
        this.a = i2;
        switch (i2) {
            case 1:
                C2466p0 c2466p0 = new C2466p0(16, new byte[16]);
                this.b = c2466p0;
                this.c = new Kn(c2466p0.b);
                this.i = 0;
                this.j = 0;
                this.k = false;
                this.o = -9223372036854775807L;
                this.d = str;
                this.e = i;
                this.f = str2;
                break;
            default:
                C2466p0 c2466p02 = new C2466p0(128, new byte[128]);
                this.b = c2466p02;
                this.c = new Kn(c2466p02.b);
                this.i = 0;
                this.o = -9223372036854775807L;
                this.d = str;
                this.e = i;
                this.f = str2;
                break;
        }
    }

    private final void b(boolean z) {
    }

    private final void c(boolean z) {
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void a(boolean z) {
        int i = this.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:169:0x0328  */
    /* JADX WARN: Removed duplicated region for block: B:191:0x036c  */
    /* JADX WARN: Removed duplicated region for block: B:194:0x0374  */
    /* JADX WARN: Removed duplicated region for block: B:219:0x03b7  */
    /* JADX WARN: Removed duplicated region for block: B:228:0x03d4  */
    @Override // com.google.android.gms.internal.ads.N2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(com.google.android.gms.internal.ads.Kn r25) {
        /*
            Method dump skipped, instructions count: 1240
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.I2.d(com.google.android.gms.internal.ads.Kn):void");
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void e(W w, C0591b1 c0591b1) {
        switch (this.a) {
            case 0:
                c0591b1.b();
                c0591b1.c();
                this.g = (String) c0591b1.e;
                c0591b1.c();
                this.h = w.q(c0591b1.c, 1);
                break;
            default:
                c0591b1.b();
                c0591b1.c();
                this.g = (String) c0591b1.e;
                c0591b1.c();
                this.h = w.q(c0591b1.c, 1);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void f(int i, long j) {
        switch (this.a) {
            case 0:
                this.o = j;
                break;
            default:
                this.o = j;
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void zze() {
        switch (this.a) {
            case 0:
                this.i = 0;
                this.j = 0;
                this.k = false;
                this.o = -9223372036854775807L;
                break;
            default:
                this.i = 0;
                this.j = 0;
                this.k = false;
                this.o = -9223372036854775807L;
                break;
        }
    }
}
