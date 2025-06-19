package androidx.transition;

import com.google.android.gms.internal.ads.AF;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.C1832aG;
import com.google.android.gms.internal.ads.C2693uD;
import com.google.android.gms.internal.ads.InterfaceC2636t;
import com.google.android.gms.internal.ads.JE;
import com.google.android.gms.internal.ads.MD;
import com.google.android.gms.internal.ads.Oo;
import com.google.android.gms.internal.ads.Ps;
import com.google.android.gms.internal.ads.XF;
import com.google.android.gms.internal.ads.YF;
import java.util.Objects;

/* loaded from: classes.dex */
public final class V {
    public int a;
    public int b;
    public boolean c;
    public boolean d;
    public Object e;
    public Object f;

    public static boolean n(JE je) {
        return je.h != 0;
    }

    public static final void o(JE je) {
        int i = je.h;
        if (i == 2) {
            AbstractC1795We.L(i == 2);
            je.h = 1;
            je.g();
        }
    }

    public void A(InterfaceC2636t interfaceC2636t) {
        JE je = (JE) this.e;
        if (je.b != 2) {
            return;
        }
        je.c(7, interfaceC2636t);
        JE je2 = (JE) this.f;
        if (je2 != null) {
            je2.c(7, interfaceC2636t);
        }
    }

    public void B(Object obj) {
        JE je = (JE) this.e;
        if (je.b != 2) {
            return;
        }
        int i = this.b;
        if (i != 4 && i != 1) {
            je.c(1, obj);
            return;
        }
        JE je2 = (JE) this.f;
        je2.getClass();
        je2.c(1, obj);
    }

    public void C() {
        int i;
        JE je = (JE) this.e;
        int i2 = je.h;
        if (i2 == 1 && this.b != 4) {
            AbstractC1795We.L(i2 == 1);
            je.h = 2;
            je.f();
            return;
        }
        JE je2 = (JE) this.f;
        if (je2 == null || (i = je2.h) != 1 || this.b == 3) {
            return;
        }
        AbstractC1795We.L(i == 1);
        je2.h = 2;
        je2.f();
    }

    public void D() {
        int i;
        AbstractC1795We.L(!f());
        if (n((JE) this.e)) {
            i = 3;
        } else {
            i = 2;
            JE je = (JE) this.f;
            if (je != null && je.h != 0) {
                i = 4;
            }
        }
        this.b = i;
    }

    public boolean a(C2693uD c2693uD) {
        JE jeJ = j(c2693uD);
        return jeJ == null || jeJ.l() || jeJ.p() || jeJ.o();
    }

    public boolean b(C2693uD c2693uD) {
        return m(c2693uD, (JE) this.e) && m(c2693uD, (JE) this.f);
    }

    public boolean c(C2693uD c2693uD) {
        JE jeJ = j(c2693uD);
        jeJ.getClass();
        return jeJ.l();
    }

    public boolean d() {
        return ((JE) this.f) != null;
    }

    public boolean e() {
        JE je = (JE) this.e;
        boolean zO = n(je) ? je.o() : true;
        JE je2 = (JE) this.f;
        return (je2 == null || je2.h == 0) ? zO : zO & je2.o();
    }

    public boolean f() {
        int i = this.b;
        return i == 2 || i == 4 || i == 3;
    }

    public boolean g(C2693uD c2693uD) {
        int i = this.b;
        return ((i == 2 || i == 4) && j(c2693uD) == ((JE) this.e)) || (this.b == 3 && j(c2693uD) == ((JE) this.f));
    }

    public boolean h() {
        int i = this.b;
        if (i == 0 || i == 2 || i == 4) {
            return n((JE) this.e);
        }
        JE je = (JE) this.f;
        je.getClass();
        return je.h != 0;
    }

    public int i(JE je, C2693uD c2693uD, YF yf, Oo oo) {
        int i;
        if (je != null && je.h != 0) {
            JE je2 = (JE) this.e;
            boolean z = je != je2;
            if (je == je2 && ((i = this.b) == 2 || i == 4)) {
                return 1;
            }
            if (je == ((JE) this.f) && this.b == 3) {
                return 1;
            }
            AF af = je.i;
            AF[] afArr = c2693uD.c;
            int i2 = this.a;
            AF af2 = afArr[i2];
            boolean zB = yf.b(i2);
            if (!zB || af != af2) {
                if (!je.n) {
                    XF xf = ((XF[]) yf.c)[i2];
                    int iG = xf != null ? xf.g() : 0;
                    C1832aG[] c1832aGArr = new C1832aG[iG];
                    for (int i3 = 0; i3 < iG; i3++) {
                        xf.getClass();
                        c1832aGArr[i3] = xf.zza(i3);
                    }
                    AF af3 = afArr[i2];
                    af3.getClass();
                    je.j(c1832aGArr, af3, c2693uD.c(), c2693uD.p, c2693uD.g.a);
                    return 3;
                }
                if (!je.o()) {
                    return 0;
                }
                k(je, oo);
                if (!zB || f()) {
                    l(!z);
                    return 1;
                }
            }
        }
        return 1;
    }

    public JE j(C2693uD c2693uD) {
        if (c2693uD != null) {
            AF af = c2693uD.c[this.a];
            if (af != null) {
                JE je = (JE) this.e;
                if (je.i == af) {
                    return je;
                }
                JE je2 = (JE) this.f;
                if (je2 != null && je2.i == af) {
                    return je2;
                }
            }
        }
        return null;
    }

    public void k(JE je, Oo oo) {
        AbstractC1795We.L(((JE) this.e) == je || ((JE) this.f) == je);
        if (n(je)) {
            if (je == ((JE) oo.e)) {
                oo.f = null;
                oo.e = null;
                oo.a = true;
            }
            o(je);
            AbstractC1795We.L(je.h == 1);
            Ps ps = je.c;
            ps.b = null;
            ps.a = null;
            je.h = 0;
            je.i = null;
            je.j = null;
            je.n = false;
            je.h0();
            je.q = null;
        }
    }

    public void l(boolean z) {
        if (z) {
            if (this.c) {
                JE je = (JE) this.e;
                AbstractC1795We.L(je.h == 0);
                Ps ps = je.c;
                ps.b = null;
                ps.a = null;
                je.e();
                this.c = false;
                return;
            }
            return;
        }
        if (this.d) {
            JE je2 = (JE) this.f;
            je2.getClass();
            AbstractC1795We.L(je2.h == 0);
            Ps ps2 = je2.c;
            ps2.b = null;
            ps2.a = null;
            je2.e();
            this.d = false;
        }
    }

    public boolean m(C2693uD c2693uD, JE je) {
        if (je == null) {
            return true;
        }
        AF[] afArr = c2693uD.c;
        int i = this.a;
        AF af = afArr[i];
        AF af2 = je.i;
        if (af2 == null) {
            return true;
        }
        if (af2 == af && (af == null || je.l())) {
            return true;
        }
        C2693uD c2693uD2 = c2693uD.m;
        return c2693uD2 != null && c2693uD2.c[i] == je.i;
    }

    public int p() {
        boolean zN = n((JE) this.e);
        int i = 0;
        JE je = (JE) this.f;
        if (je != null && je.h != 0) {
            i = 1;
        }
        return (zN ? 1 : 0) + i;
    }

    public void q() {
        int i = ((JE) this.e).b;
    }

    public int r(C2693uD c2693uD, YF yf, Oo oo) {
        int i = i((JE) this.e, c2693uD, yf, oo);
        return i == 1 ? i((JE) this.f, c2693uD, yf, oo) : i;
    }

    public void s() {
        JE je = (JE) this.e;
        if (n(je)) {
            je.g0();
            return;
        }
        JE je2 = (JE) this.f;
        if (je2 == null || je2.h == 0) {
            return;
        }
        je2.g0();
    }

    public void t() {
        int i = this.b;
        if (i != 3 && i != 4) {
            if (i == 2) {
                this.b = 0;
                return;
            }
            return;
        }
        boolean z = i == 4;
        JE je = (JE) this.e;
        JE je2 = (JE) this.f;
        if (z) {
            je2.getClass();
            je2.c(17, je);
        } else {
            je2.getClass();
            je.c(17, je2);
        }
        this.b = this.b != 4 ? 1 : 0;
    }

    public void u(YF yf, YF yf2) {
        int i;
        int i2 = this.a;
        boolean zB = yf.b(i2);
        boolean zB2 = yf2.b(i2);
        JE je = (JE) this.e;
        JE je2 = (JE) this.f;
        if (je2 == null || (i = this.b) == 3 || (i == 0 && n(je))) {
            je2 = je;
        }
        if (!zB || je2.n) {
            return;
        }
        int i3 = je.b;
        MD md = ((MD[]) yf.b)[i2];
        MD md2 = ((MD[]) yf2.b)[i2];
        if (zB2 && Objects.equals(md2, md) && !f()) {
            return;
        }
        je2.n = true;
    }

    public void v() {
        JE je = (JE) this.e;
        AbstractC1795We.L(je.h == 0);
        je.d();
        this.c = false;
        JE je2 = (JE) this.f;
        if (je2 != null) {
            AbstractC1795We.L(je2.h == 0);
            je2.d();
            this.d = false;
        }
    }

    public void w(long j, long j2) {
        JE je = (JE) this.e;
        if (n(je)) {
            je.n(j, j2);
        }
        JE je2 = (JE) this.f;
        if (je2 == null || je2.h == 0) {
            return;
        }
        je2.n(j, j2);
    }

    public void x() {
        if (!n((JE) this.e)) {
            l(true);
        }
        JE je = (JE) this.f;
        if (je == null || je.h != 0) {
            return;
        }
        l(false);
    }

    public void y() {
        int i;
        JE je = (JE) this.e;
        if (n(je) && (i = this.b) != 4 && i != 2) {
            je.n = true;
        }
        JE je2 = (JE) this.f;
        if (je2 == null || je2.h == 0 || this.b == 3) {
            return;
        }
        je2.n = true;
    }

    public void z(C2693uD c2693uD) {
        JE jeJ = j(c2693uD);
        jeJ.getClass();
        jeJ.n = true;
    }
}
