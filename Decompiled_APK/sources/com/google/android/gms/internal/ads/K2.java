package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class K2 implements N2 {
    public static final byte[] x = {73, 68, 51};
    public final boolean a;
    public final String d;
    public final int e;
    public final String f;
    public String g;
    public InterfaceC2380n0 h;
    public InterfaceC2380n0 i;
    public boolean m;
    public boolean n;
    public int q;
    public boolean r;
    public int t;
    public InterfaceC2380n0 v;
    public long w;
    public final C2466p0 b = new C2466p0(7, new byte[7]);
    public final Kn c = new Kn(Arrays.copyOf(x, 10));
    public int o = -1;
    public int p = -1;
    public long s = -9223372036854775807L;
    public long u = -9223372036854775807L;
    public int j = 0;
    public int k = 0;
    public int l = 256;

    public K2(String str, int i, String str2, boolean z) {
        this.a = z;
        this.d = str;
        this.e = i;
        this.f = str2;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void a(boolean z) {
    }

    /* JADX WARN: Code restructure failed: missing block: B:106:0x029d, code lost:
    
        r22.q = (r8 & 8) >> 3;
        r4 = r21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:107:0x02a9, code lost:
    
        if (r4 == ((r8 & 1) ^ 1)) goto L109;
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x02ab, code lost:
    
        r3 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x02ad, code lost:
    
        r3 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x02ae, code lost:
    
        r22.m = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:111:0x02b2, code lost:
    
        if (r22.n != false) goto L113;
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x02b4, code lost:
    
        r22.j = r4;
        r22.k = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:113:0x02ba, code lost:
    
        r22.j = r17;
        r22.k = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x02c1, code lost:
    
        r23.j(r15);
        r3 = r2;
        r5 = r4;
        r2 = 0;
        r4 = 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x021c, code lost:
    
        r2 = -1;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r23v0, types: [com.google.android.gms.internal.ads.Kn] */
    /* JADX WARN: Type inference failed for: r2v0 */
    /* JADX WARN: Type inference failed for: r2v1, types: [boolean] */
    /* JADX WARN: Type inference failed for: r2v10 */
    /* JADX WARN: Type inference failed for: r2v11 */
    /* JADX WARN: Type inference failed for: r2v14 */
    /* JADX WARN: Type inference failed for: r2v2 */
    /* JADX WARN: Type inference failed for: r2v3, types: [int] */
    /* JADX WARN: Type inference failed for: r2v6 */
    /* JADX WARN: Type inference failed for: r2v9 */
    /* JADX WARN: Type inference failed for: r3v22 */
    /* JADX WARN: Type inference failed for: r3v23, types: [boolean] */
    /* JADX WARN: Type inference failed for: r3v28 */
    /* JADX WARN: Type inference failed for: r5v0 */
    /* JADX WARN: Type inference failed for: r5v1, types: [boolean] */
    /* JADX WARN: Type inference failed for: r5v10 */
    /* JADX WARN: Type inference failed for: r5v13 */
    /* JADX WARN: Type inference failed for: r5v15 */
    /* JADX WARN: Type inference failed for: r5v17 */
    /* JADX WARN: Type inference failed for: r5v2 */
    /* JADX WARN: Type inference failed for: r5v3 */
    /* JADX WARN: Type inference failed for: r5v4 */
    /* JADX WARN: Type inference failed for: r5v40 */
    /* JADX WARN: Type inference failed for: r5v8 */
    @Override // com.google.android.gms.internal.ads.N2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(com.google.android.gms.internal.ads.Kn r23) {
        /*
            Method dump skipped, instructions count: 830
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.K2.d(com.google.android.gms.internal.ads.Kn):void");
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void e(W w, C0591b1 c0591b1) {
        c0591b1.b();
        c0591b1.c();
        this.g = (String) c0591b1.e;
        c0591b1.c();
        InterfaceC2380n0 interfaceC2380n0Q = w.q(c0591b1.c, 1);
        this.h = interfaceC2380n0Q;
        this.v = interfaceC2380n0Q;
        if (!this.a) {
            this.i = new T();
            return;
        }
        c0591b1.b();
        c0591b1.c();
        InterfaceC2380n0 interfaceC2380n0Q2 = w.q(c0591b1.c, 5);
        this.i = interfaceC2380n0Q2;
        EF ef = new EF();
        c0591b1.c();
        ef.a = (String) c0591b1.e;
        ef.a(this.f);
        ef.d("application/id3");
        interfaceC2380n0Q2.a(new C1832aG(ef));
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void f(int i, long j) {
        this.u = j;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void zze() {
        this.u = -9223372036854775807L;
        this.n = false;
        this.j = 0;
        this.k = 0;
        this.l = 256;
    }
}
