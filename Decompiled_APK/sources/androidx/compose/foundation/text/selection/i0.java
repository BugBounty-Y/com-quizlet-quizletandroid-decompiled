package androidx.compose.foundation.text.selection;

import android.view.ActionMode;
import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.K0;
import androidx.compose.foundation.text.Q0;
import androidx.compose.foundation.text.R0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.platform.C0942g;
import androidx.compose.ui.platform.InterfaceC0949j0;
import androidx.compose.ui.platform.S0;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.D5;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class i0 {
    public final Q0 a;
    public C0492h0 d;
    public InterfaceC0949j0 g;
    public S0 h;
    public androidx.compose.ui.hapticfeedback.a i;
    public androidx.compose.ui.focus.p j;
    public final InterfaceC0773a0 k;
    public final InterfaceC0773a0 l;
    public long m;
    public Integer n;
    public long o;
    public final InterfaceC0773a0 p;
    public final InterfaceC0773a0 q;
    public int r;
    public androidx.compose.ui.text.input.A s;
    public f0 t;
    public final h0 u;
    public final com.quizlet.data.repository.school.membership.a v;
    public androidx.compose.ui.text.input.s b = R0.a;
    public kotlin.jvm.internal.r c = K.e;
    public final InterfaceC0773a0 e = C0776c.z(new androidx.compose.ui.text.input.A(7, 0, (String) null));
    public androidx.compose.ui.text.input.K f = androidx.compose.ui.text.input.J.a;

    public i0(Q0 q0) {
        this.a = q0;
        Boolean bool = Boolean.TRUE;
        this.k = C0776c.z(bool);
        this.l = C0776c.z(bool);
        this.m = 0L;
        this.o = 0L;
        this.p = C0776c.z(null);
        this.q = C0776c.z(null);
        this.r = -1;
        this.s = new androidx.compose.ui.text.input.A(7, 0L, (String) null);
        this.u = new h0(this, 1);
        this.v = new com.quizlet.data.repository.school.membership.a(this, 8);
    }

    public static final void a(i0 i0Var, androidx.compose.ui.geometry.b bVar) {
        ((L0) i0Var.q).setValue(bVar);
    }

    public static final void b(i0 i0Var, androidx.compose.foundation.text.U u) {
        ((L0) i0Var.p).setValue(u);
    }

    /* JADX WARN: Type inference failed for: r4v12, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public static final long c(i0 i0Var, androidx.compose.ui.text.input.A a, long j, boolean z, boolean z2, r rVar, boolean z3) {
        K0 k0D;
        long j2;
        char c;
        androidx.compose.ui.text.H h;
        C0536q c0536q;
        boolean z4;
        boolean z5;
        androidx.compose.ui.hapticfeedback.a aVar;
        int i;
        C0492h0 c0492h0 = i0Var.d;
        if (c0492h0 == null || (k0D = c0492h0.d()) == null) {
            return androidx.compose.ui.text.K.b;
        }
        androidx.compose.ui.text.input.s sVar = i0Var.b;
        long j3 = a.b;
        int i2 = androidx.compose.ui.text.K.c;
        int iP = sVar.p((int) (j3 >> 32));
        androidx.compose.ui.text.input.s sVar2 = i0Var.b;
        long j4 = a.b;
        long jC = AbstractC3205m5.c(iP, sVar2.p((int) (j4 & 4294967295L)));
        int iB = k0D.b(j, false);
        int i3 = (z2 || z) ? iB : (int) (jC >> 32);
        int i4 = (!z2 || z) ? iB : (int) (jC & 4294967295L);
        f0 f0Var = i0Var.t;
        int i5 = (z || f0Var == null || (i = i0Var.r) == -1) ? -1 : i;
        androidx.compose.ui.text.H h2 = k0D.a;
        if (z) {
            h = h2;
            c0536q = null;
            c = ' ';
            j2 = 4294967295L;
        } else {
            j2 = 4294967295L;
            int i6 = (int) (jC >> 32);
            c = ' ';
            int i7 = (int) (jC & 4294967295L);
            h = h2;
            c0536q = new C0536q(new C0535p(W.u(h2, i6), i6, 1L), new C0535p(W.u(h2, i7), i7, 1L), androidx.compose.ui.text.K.f(jC));
        }
        f0 f0Var2 = new f0(z2, 1, 1, c0536q, new C0534o(1L, 1, i3, i4, i5, h));
        if (f0Var2.g(f0Var)) {
            i0Var.t = f0Var2;
            i0Var.r = iB;
            C0536q c0536qA = rVar.a(f0Var2);
            long jC2 = AbstractC3205m5.c(i0Var.b.g(c0536qA.a.b), i0Var.b.g(c0536qA.b.b));
            if (!androidx.compose.ui.text.K.a(jC2, j4)) {
                boolean z6 = androidx.compose.ui.text.K.f(jC2) != androidx.compose.ui.text.K.f(j4) && androidx.compose.ui.text.K.a(AbstractC3205m5.c((int) (jC2 & j2), (int) (jC2 >> c)), j4);
                boolean z7 = androidx.compose.ui.text.K.b(jC2) && androidx.compose.ui.text.K.b(j4);
                C0995g c0995g = a.a;
                if (z3 && c0995g.a.length() > 0 && !z6 && !z7 && (aVar = i0Var.i) != null) {
                    ((androidx.compose.ui.hapticfeedback.b) aVar).a();
                }
                i0Var.c.invoke(e(c0995g, jC2));
                if (!z3) {
                    i0Var.r(!androidx.compose.ui.text.K.b(jC2));
                }
                C0492h0 c0492h02 = i0Var.d;
                if (c0492h02 != null) {
                    ((L0) c0492h02.q).setValue(Boolean.valueOf(z3));
                }
                C0492h0 c0492h03 = i0Var.d;
                if (c0492h03 != null) {
                    ((L0) c0492h03.m).setValue(Boolean.valueOf(!androidx.compose.ui.text.K.b(jC2) && W.w(i0Var, true)));
                }
                C0492h0 c0492h04 = i0Var.d;
                if (c0492h04 == null) {
                    z4 = false;
                } else {
                    if (androidx.compose.ui.text.K.b(jC2)) {
                        z4 = false;
                    } else {
                        z4 = false;
                        if (W.w(i0Var, false)) {
                            z5 = true;
                        }
                        ((L0) c0492h04.n).setValue(Boolean.valueOf(z5));
                    }
                    z5 = z4;
                    ((L0) c0492h04.n).setValue(Boolean.valueOf(z5));
                }
                C0492h0 c0492h05 = i0Var.d;
                if (c0492h05 == null) {
                    return jC2;
                }
                ((L0) c0492h05.o).setValue(Boolean.valueOf((androidx.compose.ui.text.K.b(jC2) && W.w(i0Var, true)) ? true : z4));
                return jC2;
            }
        }
        return j4;
    }

    public static androidx.compose.ui.text.input.A e(C0995g c0995g, long j) {
        return new androidx.compose.ui.text.input.A(c0995g, j, (androidx.compose.ui.text.K) null);
    }

    /* JADX WARN: Type inference failed for: r0v7, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public final void d(boolean z) {
        if (androidx.compose.ui.text.K.b(l().b)) {
            return;
        }
        InterfaceC0949j0 interfaceC0949j0 = this.g;
        if (interfaceC0949j0 != null) {
            ((C0942g) interfaceC0949j0).a(D5.b(l()));
        }
        if (z) {
            int iD = androidx.compose.ui.text.K.d(l().b);
            this.c.invoke(e(l().a, AbstractC3205m5.c(iD, iD)));
            p(androidx.compose.foundation.text.V.a);
        }
    }

    /* JADX WARN: Type inference failed for: r1v10, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public final void f() {
        if (androidx.compose.ui.text.K.b(l().b)) {
            return;
        }
        InterfaceC0949j0 interfaceC0949j0 = this.g;
        if (interfaceC0949j0 != null) {
            ((C0942g) interfaceC0949j0).a(D5.b(l()));
        }
        C0995g c0995gD = D5.d(l(), l().a.a.length());
        C0995g c0995gC = D5.c(l(), l().a.a.length());
        C0984d c0984d = new C0984d(c0995gD);
        c0984d.d(c0995gC);
        C0995g c0995gJ = c0984d.j();
        int iE = androidx.compose.ui.text.K.e(l().b);
        this.c.invoke(e(c0995gJ, AbstractC3205m5.c(iE, iE)));
        p(androidx.compose.foundation.text.V.a);
        this.a.e = true;
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public final void g(androidx.compose.ui.geometry.b bVar) {
        if (!androidx.compose.ui.text.K.b(l().b)) {
            C0492h0 c0492h0 = this.d;
            K0 k0D = c0492h0 != null ? c0492h0.d() : null;
            int iD = (bVar == null || k0D == null) ? androidx.compose.ui.text.K.d(l().b) : this.b.g(k0D.b(bVar.a, true));
            this.c.invoke(androidx.compose.ui.text.input.A.a(l(), null, AbstractC3205m5.c(iD, iD), 5));
        }
        p((bVar == null || l().a.a.length() <= 0) ? androidx.compose.foundation.text.V.a : androidx.compose.foundation.text.V.c);
        r(false);
    }

    public final void h(boolean z) {
        androidx.compose.ui.focus.p pVar;
        C0492h0 c0492h0 = this.d;
        if (c0492h0 != null && !c0492h0.b() && (pVar = this.j) != null) {
            pVar.b();
        }
        this.s = l();
        r(z);
        p(androidx.compose.foundation.text.V.b);
    }

    public final androidx.compose.ui.geometry.b i() {
        return (androidx.compose.ui.geometry.b) ((L0) this.q).getValue();
    }

    public final boolean j() {
        return ((Boolean) ((L0) this.l).getValue()).booleanValue();
    }

    public final long k(boolean z) {
        K0 k0D;
        long j;
        C0492h0 c0492h0 = this.d;
        if (c0492h0 == null || (k0D = c0492h0.d()) == null) {
            return 9205357640488583168L;
        }
        androidx.compose.ui.text.H h = k0D.a;
        C0492h0 c0492h02 = this.d;
        C0995g c0995g = c0492h02 != null ? c0492h02.a.a : null;
        if (c0995g == null) {
            return 9205357640488583168L;
        }
        if (!Intrinsics.b(c0995g.a, h.a.a.a)) {
            return 9205357640488583168L;
        }
        androidx.compose.ui.text.input.A aL = l();
        if (z) {
            long j2 = aL.b;
            int i = androidx.compose.ui.text.K.c;
            j = j2 >> 32;
        } else {
            long j3 = aL.b;
            int i2 = androidx.compose.ui.text.K.c;
            j = j3 & 4294967295L;
        }
        return W.t(h, this.b.p((int) j), z, androidx.compose.ui.text.K.f(l().b));
    }

    public final androidx.compose.ui.text.input.A l() {
        return (androidx.compose.ui.text.input.A) ((L0) this.e).getValue();
    }

    public final void m() {
        S0 s0 = this.h;
        if ((s0 != null ? ((androidx.compose.ui.platform.W) s0).d : 0) != 1 || s0 == null) {
            return;
        }
        androidx.compose.ui.platform.W w = (androidx.compose.ui.platform.W) s0;
        w.d = 2;
        ActionMode actionMode = w.b;
        if (actionMode != null) {
            actionMode.finish();
        }
        w.b = null;
    }

    /* JADX WARN: Removed duplicated region for block: B:71:0x015b  */
    /* JADX WARN: Type inference failed for: r2v12, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void n() {
        /*
            Method dump skipped, instructions count: 828
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.i0.n():void");
    }

    /* JADX WARN: Type inference failed for: r1v5, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public final void o() {
        androidx.compose.ui.text.input.A aE = e(l().a, AbstractC3205m5.c(0, l().a.a.length()));
        this.c.invoke(aE);
        this.s = androidx.compose.ui.text.input.A.a(this.s, null, aE.b, 5);
        h(true);
    }

    public final void p(androidx.compose.foundation.text.V v) {
        C0492h0 c0492h0 = this.d;
        if (c0492h0 != null) {
            if (c0492h0.a() == v) {
                c0492h0 = null;
            }
            if (c0492h0 != null) {
                ((L0) c0492h0.k).setValue(v);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x01a0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void q() {
        /*
            Method dump skipped, instructions count: 432
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.i0.q():void");
    }

    public final void r(boolean z) {
        C0492h0 c0492h0 = this.d;
        if (c0492h0 != null) {
            ((L0) c0492h0.l).setValue(Boolean.valueOf(z));
        }
        if (z) {
            q();
        } else {
            m();
        }
    }
}
