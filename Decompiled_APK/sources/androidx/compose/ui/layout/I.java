package androidx.compose.ui.layout;

import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class I implements r {
    public final androidx.compose.ui.node.P a;

    public I(androidx.compose.ui.node.P p) {
        this.a = p;
    }

    @Override // androidx.compose.ui.layout.r
    public final long E(long j) {
        return androidx.compose.ui.geometry.b.h(this.a.l.E(j), a());
    }

    @Override // androidx.compose.ui.layout.r
    public final void F(r rVar, float[] fArr) {
        this.a.l.F(rVar, fArr);
    }

    @Override // androidx.compose.ui.layout.r
    public final r H() {
        androidx.compose.ui.node.P pU0;
        if (!k()) {
            W4.f("LayoutCoordinate operations are only valid when isAttached is true");
            throw null;
        }
        androidx.compose.ui.node.a0 a0Var = ((androidx.compose.ui.node.a0) this.a.l.l.w.d).n;
        if (a0Var == null || (pU0 = a0Var.U0()) == null) {
            return null;
        }
        return pU0.o;
    }

    @Override // androidx.compose.ui.layout.r
    public final long N(long j) {
        return androidx.compose.ui.geometry.b.h(this.a.l.N(j), a());
    }

    @Override // androidx.compose.ui.layout.r
    public final long U(long j) {
        return this.a.l.U(androidx.compose.ui.geometry.b.h(j, a()));
    }

    public final long a() {
        androidx.compose.ui.node.P p = this.a;
        androidx.compose.ui.node.P pI = AbstractC0897s.i(p);
        return androidx.compose.ui.geometry.b.g(b(pI.o, 0L), p.l.e1(pI.l, 0L));
    }

    public final long b(r rVar, long j) {
        boolean z = rVar instanceof I;
        androidx.compose.ui.node.P p = this.a;
        if (!z) {
            androidx.compose.ui.node.P pI = AbstractC0897s.i(p);
            long jB = b(pI.o, j);
            androidx.compose.ui.node.a0 a0Var = pI.l;
            a0Var.getClass();
            return androidx.compose.ui.geometry.b.h(jB, a0Var.e1(rVar, 0L));
        }
        androidx.compose.ui.node.P p2 = ((I) rVar).a;
        p2.l.f1();
        androidx.compose.ui.node.P pU0 = p.l.S0(p2.l).U0();
        if (pU0 != null) {
            long jC = androidx.compose.ui.unit.h.c(androidx.compose.ui.unit.h.d(p2.N0(pU0, false), P5.e(j)), p.N0(pU0, false));
            return Q4.c((int) (jC >> 32), (int) (jC & 4294967295L));
        }
        androidx.compose.ui.node.P pI2 = AbstractC0897s.i(p2);
        long jD = androidx.compose.ui.unit.h.d(androidx.compose.ui.unit.h.d(p2.N0(pI2, false), pI2.m), P5.e(j));
        androidx.compose.ui.node.P pI3 = AbstractC0897s.i(p);
        long jC2 = androidx.compose.ui.unit.h.c(jD, androidx.compose.ui.unit.h.d(p.N0(pI3, false), pI3.m));
        long jC3 = Q4.c((int) (jC2 >> 32), (int) (jC2 & 4294967295L));
        androidx.compose.ui.node.a0 a0Var2 = pI3.l.n;
        Intrinsics.d(a0Var2);
        androidx.compose.ui.node.a0 a0Var3 = pI2.l.n;
        Intrinsics.d(a0Var3);
        return a0Var2.e1(a0Var3, jC3);
    }

    @Override // androidx.compose.ui.layout.r
    public final long d(long j) {
        return this.a.l.d(androidx.compose.ui.geometry.b.h(j, a()));
    }

    @Override // androidx.compose.ui.layout.r
    public final long f(r rVar, long j) {
        return b(rVar, j);
    }

    @Override // androidx.compose.ui.layout.r
    public final r h() {
        androidx.compose.ui.node.P pU0;
        if (!k()) {
            W4.f("LayoutCoordinate operations are only valid when isAttached is true");
            throw null;
        }
        androidx.compose.ui.node.a0 a0Var = this.a.l.n;
        if (a0Var == null || (pU0 = a0Var.U0()) == null) {
            return null;
        }
        return pU0.o;
    }

    @Override // androidx.compose.ui.layout.r
    public final boolean k() {
        return this.a.l.W0().m;
    }

    @Override // androidx.compose.ui.layout.r
    public final void m(float[] fArr) {
        this.a.l.m(fArr);
    }

    @Override // androidx.compose.ui.layout.r
    public final androidx.compose.ui.geometry.c o(r rVar, boolean z) {
        return this.a.l.o(rVar, z);
    }

    @Override // androidx.compose.ui.layout.r
    public final long t() {
        androidx.compose.ui.node.P p = this.a;
        return R5.a(p.a, p.b);
    }
}
