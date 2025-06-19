package androidx.compose.foundation;

import androidx.compose.animation.core.C0242g;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.InterfaceC0920p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class W extends AbstractC0918n implements androidx.compose.ui.focus.d, androidx.compose.ui.node.n0, InterfaceC0920p, androidx.compose.ui.focus.q {
    public androidx.compose.ui.focus.s p;
    public final T q;
    public final X r;
    public final Y s;

    public W(androidx.compose.foundation.interaction.l lVar) {
        T t = new T();
        t.n = lVar;
        M0(t);
        this.q = t;
        X x = new X();
        M0(x);
        this.r = x;
        Y y = new Y();
        M0(y);
        this.s = y;
        M0(new androidx.compose.ui.focus.t());
    }

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    public final void P0(androidx.compose.foundation.interaction.l lVar) {
        androidx.compose.foundation.interaction.d dVar;
        T t = this.q;
        if (Intrinsics.b(t.n, lVar)) {
            return;
        }
        androidx.compose.foundation.interaction.l lVar2 = t.n;
        if (lVar2 != null && (dVar = t.o) != null) {
            lVar2.a(new androidx.compose.foundation.interaction.e(dVar));
        }
        t.o = null;
        t.n = lVar;
    }

    @Override // androidx.compose.ui.focus.d
    public final void d0(androidx.compose.ui.focus.s sVar) {
        Z zM0;
        if (Intrinsics.b(this.p, sVar)) {
            return;
        }
        boolean zA = sVar.a();
        androidx.compose.foundation.lazy.layout.Y y = null;
        if (zA) {
            kotlinx.coroutines.E.A(A0(), null, null, new V(this, null), 3);
        }
        if (this.m) {
            AbstractC0910f.p(this);
        }
        T t = this.q;
        androidx.compose.foundation.interaction.l lVar = t.n;
        if (lVar != null) {
            if (zA) {
                androidx.compose.foundation.interaction.d dVar = t.o;
                if (dVar != null) {
                    t.M0(lVar, new androidx.compose.foundation.interaction.e(dVar));
                    t.o = null;
                }
                androidx.compose.foundation.interaction.d dVar2 = new androidx.compose.foundation.interaction.d();
                t.M0(lVar, dVar2);
                t.o = dVar2;
            } else {
                androidx.compose.foundation.interaction.d dVar3 = t.o;
                if (dVar3 != null) {
                    t.M0(lVar, new androidx.compose.foundation.interaction.e(dVar3));
                    t.o = null;
                }
            }
        }
        Y y2 = this.s;
        if (zA != y2.n) {
            if (zA) {
                androidx.compose.ui.node.a0 a0Var = y2.o;
                if (a0Var != null && a0Var.W0().m && (zM0 = y2.M0()) != null) {
                    zM0.M0(y2.o);
                }
            } else {
                Z zM02 = y2.M0();
                if (zM02 != null) {
                    zM02.M0(null);
                }
            }
            y2.n = zA;
        }
        X x = this.r;
        if (zA) {
            x.getClass();
            kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
            AbstractC0910f.s(x, new C0242g(1, j, x));
            androidx.compose.foundation.lazy.layout.Y y3 = (androidx.compose.foundation.lazy.layout.Y) j.a;
            if (y3 != null) {
                y3.b();
                y = y3;
            }
            x.n = y;
        } else {
            androidx.compose.foundation.lazy.layout.Y y4 = x.n;
            if (y4 != null) {
                y4.c();
            }
            x.n = null;
        }
        x.o = zA;
        this.p = sVar;
    }

    @Override // androidx.compose.ui.node.n0
    public final void r0(androidx.compose.ui.semantics.v vVar) {
        int i = 4;
        androidx.compose.ui.focus.s sVar = this.p;
        boolean z = false;
        if (sVar != null && sVar.a()) {
            z = true;
        }
        kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
        androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.k;
        kotlin.reflect.n nVar = androidx.compose.ui.semantics.t.a[4];
        uVar.a(vVar, Boolean.valueOf(z));
        ((androidx.compose.ui.semantics.k) vVar).b(androidx.compose.ui.semantics.j.u, new androidx.compose.ui.semantics.a(null, new androidx.compose.animation.core.K(this, i)));
    }

    @Override // androidx.compose.ui.node.InterfaceC0920p
    public final void y0(androidx.compose.ui.node.a0 a0Var) {
        this.s.y0(a0Var);
    }
}
