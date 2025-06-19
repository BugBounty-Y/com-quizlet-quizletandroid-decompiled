package androidx.compose.ui.node;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.core.C0242g;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.layout.C0893n;
import androidx.compose.ui.platform.C0971v;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class K extends androidx.compose.ui.layout.W implements androidx.compose.ui.layout.J, InterfaceC0905a, U {
    public boolean A;
    public Function1 B;
    public androidx.compose.ui.graphics.layer.b C;
    public float E;
    public final C0242g F;
    public boolean G;
    public final /* synthetic */ L H;
    public boolean f;
    public boolean i;
    public boolean j;
    public boolean l;
    public Function1 n;
    public androidx.compose.ui.graphics.layer.b o;
    public float p;
    public Object r;
    public boolean s;
    public boolean t;
    public boolean x;
    public float z;
    public int g = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public int h = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public int k = 3;
    public long m = 0;
    public boolean q = true;
    public final F u = new F(this, 0);
    public final androidx.compose.runtime.collection.b v = new androidx.compose.runtime.collection.b(new K[16]);
    public boolean w = true;
    public final androidx.compose.ui.input.nestedscroll.b y = new androidx.compose.ui.input.nestedscroll.b(this, 5);
    public long D = 0;

    public K(L l) {
        this.H = l;
        this.F = new C0242g(21, l, this);
    }

    public final void A0() {
        boolean z = this.s;
        this.s = true;
        E e = this.H.a;
        if (!z) {
            L l = e.x;
            if (l.d) {
                E.T(e, true, 6);
            } else if (l.g) {
                E.R(e, true, 6);
            }
        }
        V v = e.w;
        a0 a0Var = ((C0923t) v.c).m;
        for (a0 a0Var2 = (a0) v.d; !Intrinsics.b(a0Var2, a0Var) && a0Var2 != null; a0Var2 = a0Var2.m) {
            if (a0Var2.C) {
                a0Var2.c1();
            }
        }
        androidx.compose.runtime.collection.b bVarW = e.w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                E e2 = (E) objArr[i2];
                if (e2.t() != Integer.MAX_VALUE) {
                    e2.x.r.A0();
                    E.U(e2);
                }
                i2++;
            } while (i2 < i);
        }
    }

    @Override // androidx.compose.ui.layout.J
    public final androidx.compose.ui.layout.W B(long j) {
        int i;
        L l = this.H;
        E e = l.a;
        if (e.H == 3) {
            e.f();
        }
        E e2 = l.a;
        if (AbstractC0910f.r(e2)) {
            J j2 = l.s;
            Intrinsics.d(j2);
            j2.i = 3;
            j2.B(j);
        }
        E eS = e2.s();
        if (eS == null) {
            this.k = 3;
        } else {
            if (this.k != 3 && !e2.v) {
                W4.f("measure() may not be called multiple times on the same Measurable. If you want to get the content size of the Measurable before calculating the final constraints, please use methods like minIntrinsicWidth()/maxIntrinsicWidth() and minIntrinsicHeight()/maxIntrinsicHeight()");
                throw null;
            }
            L l2 = eS.x;
            int iK = AbstractC0147y.k(l2.c);
            if (iK != 0) {
                i = 2;
                if (iK != 2) {
                    throw new IllegalStateException("Measurable could be only measured from the parent's measure or layout block. Parents state is ".concat(B.w(l2.c)));
                }
            } else {
                i = 1;
            }
            this.k = i;
        }
        H0(j);
        return this;
    }

    public final void B0() {
        if (this.s) {
            int i = 0;
            this.s = false;
            L l = this.H;
            V v = l.a.w;
            a0 a0Var = ((C0923t) v.c).m;
            for (a0 a0Var2 = (a0) v.d; !Intrinsics.b(a0Var2, a0Var) && a0Var2 != null; a0Var2 = a0Var2.m) {
                if (a0Var2.D != null) {
                    if (a0Var2.E != null) {
                        a0Var2.E = null;
                    }
                    a0Var2.r1(null, false);
                    a0Var2.l.S(false);
                }
            }
            androidx.compose.runtime.collection.b bVarW = l.a.w();
            int i2 = bVarW.c;
            if (i2 > 0) {
                Object[] objArr = bVarW.a;
                do {
                    ((E) objArr[i]).x.r.B0();
                    i++;
                } while (i < i2);
            }
        }
    }

    public final void C0() {
        androidx.compose.runtime.collection.b bVarW;
        int i;
        L l = this.H;
        if (l.n <= 0 || (i = (bVarW = l.a.w()).c) <= 0) {
            return;
        }
        Object[] objArr = bVarW.a;
        int i2 = 0;
        do {
            E e = (E) objArr[i2];
            L l2 = e.x;
            if ((l2.l || l2.m) && !l2.e) {
                e.S(false);
            }
            l2.r.C0();
            i2++;
        } while (i2 < i);
    }

    public final void D0() {
        int i;
        L l = this.H;
        E.T(l.a, false, 7);
        E e = l.a;
        E eS = e.s();
        if (eS == null || e.H != 3) {
            return;
        }
        int iK = AbstractC0147y.k(eS.x.c);
        if (iK != 0) {
            i = 2;
            if (iK != 2) {
                i = eS.H;
            }
        } else {
            i = 1;
        }
        e.H = i;
    }

    public final void E0() {
        this.A = true;
        L l = this.H;
        E eS = l.a.s();
        float f = e().x;
        V v = l.a.w;
        a0 a0Var = (a0) v.d;
        while (a0Var != ((C0923t) v.c)) {
            Intrinsics.e(a0Var, "null cannot be cast to non-null type androidx.compose.ui.node.LayoutModifierNodeCoordinator");
            C0928y c0928y = (C0928y) a0Var;
            f += c0928y.x;
            a0Var = c0928y.m;
        }
        if (f != this.z) {
            this.z = f;
            if (eS != null) {
                eS.K();
            }
            if (eS != null) {
                eS.z();
            }
        }
        if (!this.s) {
            if (eS != null) {
                eS.z();
            }
            A0();
            if (this.f && eS != null) {
                eS.S(false);
            }
        }
        if (eS == null) {
            this.h = 0;
        } else if (!this.f) {
            L l2 = eS.x;
            if (l2.c == 3) {
                if (this.h != Integer.MAX_VALUE) {
                    W4.f("Place was called on a node which was placed already");
                    throw null;
                }
                int i = l2.k;
                this.h = i;
                l2.k = i + 1;
            }
        }
        L();
    }

    public final void F0(long j, float f, Function1 function1, androidx.compose.ui.graphics.layer.b bVar) {
        L l = this.H;
        E e = l.a;
        if (e.G) {
            W4.e("place is called on a deactivated node");
            throw null;
        }
        l.c = 3;
        this.m = j;
        this.p = f;
        this.n = function1;
        this.o = bVar;
        this.j = true;
        this.A = false;
        g0 g0VarA = H.a(e);
        if (l.e || !this.s) {
            this.u.g = false;
            l.d(false);
            this.B = function1;
            this.D = j;
            this.E = f;
            this.C = bVar;
            i0 snapshotObserver = ((C0971v) g0VarA).getSnapshotObserver();
            snapshotObserver.a(l.a, snapshotObserver.f, this.F);
        } else {
            a0 a0VarA = l.a();
            a0VarA.j1(androidx.compose.ui.unit.h.d(j, a0VarA.e), f, function1, bVar);
            E0();
        }
        l.c = 5;
    }

    @Override // androidx.compose.ui.layout.W, androidx.compose.ui.layout.J
    public final Object G() {
        return this.r;
    }

    public final void G0(long j, float f, Function1 function1, androidx.compose.ui.graphics.layer.b bVar) {
        androidx.compose.ui.layout.V placementScope;
        this.t = true;
        boolean zB = androidx.compose.ui.unit.h.b(j, this.m);
        L l = this.H;
        if (!zB || this.G) {
            if (l.m || l.l || this.G) {
                l.e = true;
                this.G = false;
            }
            C0();
        }
        if (AbstractC0910f.r(l.a)) {
            a0 a0Var = l.a().n;
            E e = l.a;
            if (a0Var == null || (placementScope = a0Var.i) == null) {
                placementScope = ((C0971v) H.a(e)).getPlacementScope();
            }
            J j2 = l.s;
            Intrinsics.d(j2);
            E eS = e.s();
            if (eS != null) {
                eS.x.j = 0;
            }
            j2.h = SubsamplingScaleImageView.TILE_SIZE_AUTO;
            androidx.compose.ui.layout.V.d(placementScope, j2, (int) (j >> 32), (int) (4294967295L & j));
        }
        J j3 = l.s;
        if (j3 == null || j3.k) {
            F0(j, f, function1, bVar);
        } else {
            W4.f("Error: Placement happened before lookahead.");
            throw null;
        }
    }

    public final boolean H0(long j) {
        boolean z = true;
        L l = this.H;
        E e = l.a;
        if (e.G) {
            W4.e("measure is called on a deactivated node");
            throw null;
        }
        g0 g0VarA = H.a(e);
        E e2 = l.a;
        E eS = e2.s();
        e2.v = e2.v || (eS != null && eS.v);
        if (!e2.x.d && androidx.compose.ui.unit.a.b(this.d, j)) {
            ((C0971v) g0VarA).H.f(e2, false);
            e2.V();
            return false;
        }
        this.u.f = false;
        androidx.compose.runtime.collection.b bVarW = e2.w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                ((E) objArr[i2]).x.r.u.c = false;
                Unit unit = Unit.a;
                i2++;
            } while (i2 < i);
        }
        this.i = true;
        long j2 = l.a().c;
        x0(j);
        if (l.c != 5) {
            W4.f("layout state is not idle before measure starts");
            throw null;
        }
        l.c = 1;
        l.d = false;
        l.t = j;
        i0 snapshotObserver = ((C0971v) H.a(e2)).getSnapshotObserver();
        snapshotObserver.a(e2, snapshotObserver.c, l.u);
        if (l.c == 1) {
            l.e = true;
            l.f = true;
            l.c = 5;
        }
        if (androidx.compose.ui.unit.j.a(l.a().c, j2) && l.a().a == this.a && l.a().b == this.b) {
            z = false;
        }
        t0(R5.a(l.a().a, l.a().b));
        return z;
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final void L() {
        androidx.compose.runtime.collection.b bVarW;
        int i;
        this.x = true;
        F f = this.u;
        f.h();
        L l = this.H;
        boolean z = l.e;
        E e = l.a;
        if (z && (i = (bVarW = e.w()).c) > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                E e2 = (E) objArr[i2];
                L l2 = e2.x;
                if (l2.d && l2.r.k == 1 && E.M(e2)) {
                    E.T(e, false, 7);
                }
                i2++;
            } while (i2 < i);
        }
        if (l.f || (!this.l && !e().h && l.e)) {
            l.e = false;
            int i3 = l.c;
            l.c = 3;
            l.e(false);
            i0 snapshotObserver = ((C0971v) H.a(e)).getSnapshotObserver();
            snapshotObserver.a(e, snapshotObserver.e, this.y);
            l.c = i3;
            if (e().h && l.l) {
                requestLayout();
            }
            l.f = false;
        }
        if (f.d) {
            f.e = true;
        }
        if (f.b && f.e()) {
            f.g();
        }
        this.x = false;
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final boolean M() {
        return this.s;
    }

    @Override // androidx.compose.ui.node.U
    public final void S(boolean z) {
        L l = this.H;
        boolean z2 = l.a().f;
        if (z != z2) {
            l.a().f = z2;
            this.G = true;
        }
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final void W() {
        E.T(this.H.a, false, 7);
    }

    @Override // androidx.compose.ui.layout.J
    public final int X(int i) {
        D0();
        return this.H.a().X(i);
    }

    @Override // androidx.compose.ui.layout.J
    public final int b(int i) {
        D0();
        return this.H.a().b(i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final F c() {
        return this.u;
    }

    @Override // androidx.compose.ui.layout.W
    public final int d0(C0893n c0893n) {
        L l = this.H;
        E eS = l.a.s();
        int i = eS != null ? eS.x.c : 0;
        F f = this.u;
        if (i == 1) {
            f.c = true;
        } else {
            E eS2 = l.a.s();
            if ((eS2 != null ? eS2.x.c : 0) == 3) {
                f.d = true;
            }
        }
        this.l = true;
        int iD0 = l.a().d0(c0893n);
        this.l = false;
        return iD0;
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final C0923t e() {
        return (C0923t) this.H.a.w.c;
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final InterfaceC0905a i() {
        L l;
        E eS = this.H.a.s();
        if (eS == null || (l = eS.x) == null) {
            return null;
        }
        return l.r;
    }

    @Override // androidx.compose.ui.layout.W
    public final int i0() {
        return this.H.a().i0();
    }

    @Override // androidx.compose.ui.layout.W
    public final int k0() {
        return this.H.a().k0();
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final void p(C0775b0 c0775b0) {
        androidx.compose.runtime.collection.b bVarW = this.H.a.w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                c0775b0.invoke(((E) objArr[i2]).x.r);
                i2++;
            } while (i2 < i);
        }
    }

    @Override // androidx.compose.ui.layout.W
    public final void r0(long j, float f, androidx.compose.ui.graphics.layer.b bVar) {
        G0(j, f, null, bVar);
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final void requestLayout() {
        this.H.a.S(false);
    }

    @Override // androidx.compose.ui.layout.W
    public final void s0(long j, float f, Function1 function1) {
        G0(j, f, function1, null);
    }

    @Override // androidx.compose.ui.layout.J
    public final int x(int i) {
        D0();
        return this.H.a().x(i);
    }

    public final List y0() {
        L l = this.H;
        l.a.a0();
        boolean z = this.w;
        androidx.compose.runtime.collection.b bVar = this.v;
        if (!z) {
            return bVar.h();
        }
        E e = l.a;
        androidx.compose.runtime.collection.b bVarW = e.w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                E e2 = (E) objArr[i2];
                if (bVar.c <= i2) {
                    bVar.b(e2.x.r);
                } else {
                    K k = e2.x.r;
                    Object[] objArr2 = bVar.a;
                    Object obj = objArr2[i2];
                    objArr2[i2] = k;
                }
                i2++;
            } while (i2 < i);
        }
        bVar.p(((androidx.compose.runtime.collection.b) ((androidx.collection.E) e.n()).b).c, bVar.c);
        this.w = false;
        return bVar.h();
    }

    @Override // androidx.compose.ui.layout.J
    public final int z(int i) {
        D0();
        return this.H.a().z(i);
    }
}
