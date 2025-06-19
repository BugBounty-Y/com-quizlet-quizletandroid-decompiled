package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0676l1;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.t0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2637t0 implements U {
    public final C1 d;
    public int e;
    public C2680u0 g;
    public long j;
    public C2766w0 k;
    public int o;
    public boolean p;
    public final boolean c = true;
    public final Kn a = new Kn(12);
    public final C0676l1 b = new C0676l1();
    public W f = new C1(16);
    public C2766w0[] i = new C2766w0[0];
    public long m = -1;
    public long n = -1;
    public int l = -1;
    public long h = -9223372036854775807L;

    public C2637t0(C1 c1) {
        this.d = c1;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) {
        Kn kn = this.a;
        ((P) v).k(kn.a, 0, 12, false);
        kn.j(0);
        if (kn.v() == 1179011410) {
            kn.k(4);
            if (kn.v() == 541677121) {
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        this.e = 0;
        if (this.c) {
            w = new androidx.browser.customtabs.k(w, this.d);
        }
        this.f = w;
        this.j = -1L;
    }

    /* JADX WARN: Removed duplicated region for block: B:190:0x03c0  */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.ads.V r31, androidx.compose.foundation.lazy.layout.C0429a r32) throws com.google.android.gms.internal.ads.zzaz, java.io.EOFException, java.io.InterruptedIOException {
        /*
            Method dump skipped, instructions count: 1131
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2637t0.f(com.google.android.gms.internal.ads.V, androidx.compose.foundation.lazy.layout.a):int");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        this.j = -1L;
        this.k = null;
        for (C2766w0 c2766w0 : this.i) {
            if (c2766w0.k == 0) {
                c2766w0.i = 0;
            } else {
                c2766w0.i = c2766w0.n[Yo.k(c2766w0.m, j, true)];
            }
        }
        if (j == 0) {
            this.e = this.i.length != 0 ? 3 : 0;
        } else {
            this.e = 6;
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        C2244ju c2244ju = AbstractC2330lu.b;
        return Bu.e;
    }
}
