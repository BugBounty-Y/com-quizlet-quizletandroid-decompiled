package com.google.android.gms.internal.ads;

import android.os.SystemClock;
import androidx.compose.ui.text.input.C1007j;
import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.ads.z, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2894z {
    public final C2722v a;
    public final C2679u b = new C2679u();
    public final androidx.compose.ui.text.android.selection.f c = new androidx.compose.ui.text.android.selection.f(4, (byte) 0);
    public final androidx.compose.ui.text.android.selection.f d = new androidx.compose.ui.text.android.selection.f(4, (byte) 0);
    public final C1007j e;
    public long f;
    public long g;
    public long h;
    public C1740Nd i;
    public long j;
    public final C1732Mb k;

    public C2894z(C1732Mb c1732Mb, C2722v c2722v) {
        this.k = c1732Mb;
        this.a = c2722v;
        C1007j c1007j = new C1007j();
        int i = 16;
        if (Integer.bitCount(16) != 1) {
            int iHighestOneBit = Integer.highestOneBit(15);
            i = iHighestOneBit + iHighestOneBit;
        }
        c1007j.b = 0;
        c1007j.c = -1;
        c1007j.d = 0;
        c1007j.f = new long[i];
        c1007j.e = i - 1;
        this.e = c1007j;
        this.f = -9223372036854775807L;
        this.i = C1740Nd.d;
        this.g = -9223372036854775807L;
        this.h = -9223372036854775807L;
    }

    public final void a(long j, long j2) {
        while (true) {
            C1007j c1007j = this.e;
            int i = c1007j.d;
            if (i == 0) {
                return;
            }
            if (i == 0) {
                throw new NoSuchElementException();
            }
            long j3 = ((long[]) c1007j.f)[c1007j.b];
            Long l = (Long) this.d.q(j3);
            if (l != null && l.longValue() != this.j) {
                this.j = l.longValue();
                this.a.d(2);
            }
            long j4 = this.j;
            C2679u c2679u = this.b;
            C2722v c2722v = this.a;
            int iA = c2722v.a(j3, j, j2, j4, false, false, c2679u);
            C1732Mb c1732Mb = this.k;
            C2077g c2077g = (C2077g) c1732Mb.c;
            if (iA == 0 || iA == 1) {
                this.g = j3;
                long j5 = c1007j.j();
                C1740Nd c1740Nd = (C1740Nd) this.c.q(j5);
                if (c1740Nd != null && !c1740Nd.equals(C1740Nd.d) && !c1740Nd.equals(this.i)) {
                    this.i = c1740Nd;
                    EF ef = new EF();
                    ef.s = c1740Nd.a;
                    ef.t = c1740Nd.b;
                    ef.d("video/raw");
                    c1732Mb.b = new C1832aG(ef);
                    c2077g.i.execute(new RunnableC2033f(c1732Mb, c1740Nd));
                }
                long jNanoTime = iA == 0 ? System.nanoTime() : c2679u.b;
                int i2 = c2722v.d;
                c2722v.d = 3;
                c2722v.k.getClass();
                c2722v.f = Yo.t(SystemClock.elapsedRealtime());
                if ((i2 != 3) && c2077g.d != null) {
                    c2077g.i.execute(new RunnableC2033f(c1732Mb, 0));
                }
                C1832aG c1832aG = (C1832aG) c1732Mb.b;
                c2077g.j.a(j5, jNanoTime, c1832aG == null ? new C1832aG(new EF()) : c1832aG, null);
                C2207j c2207j = (C2207j) c2077g.c.remove();
                c2207j.c.t0(c2207j.a, c2207j.b, jNanoTime);
            } else if (iA == 2 || iA == 3) {
                this.g = j3;
                c1007j.j();
                c2077g.i.execute(new RunnableC2033f(c1732Mb, 1));
                C2207j c2207j2 = (C2207j) c2077g.c.remove();
                c2207j2.c.k0(c2207j2.a, c2207j2.b);
            } else if (iA != 4) {
                return;
            } else {
                this.g = j3;
            }
        }
    }
}
