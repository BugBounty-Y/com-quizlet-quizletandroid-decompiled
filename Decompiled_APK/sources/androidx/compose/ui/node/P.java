package androidx.compose.ui.node;

import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.LinkedHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class P extends O implements androidx.compose.ui.layout.J {
    public final a0 l;
    public LinkedHashMap n;
    public androidx.compose.ui.layout.L p;
    public long m = 0;
    public final androidx.compose.ui.layout.I o = new androidx.compose.ui.layout.I(this);
    public final LinkedHashMap q = new LinkedHashMap();

    public P(a0 a0Var) {
        this.l = a0Var;
    }

    public static final void K0(P p, androidx.compose.ui.layout.L l) {
        Unit unit;
        LinkedHashMap linkedHashMap;
        if (l != null) {
            p.t0(R5.a(l.getWidth(), l.b()));
            unit = Unit.a;
        } else {
            unit = null;
        }
        if (unit == null) {
            p.t0(0L);
        }
        if (!Intrinsics.b(p.p, l) && l != null && ((((linkedHashMap = p.n) != null && !linkedHashMap.isEmpty()) || !l.c().isEmpty()) && !Intrinsics.b(l.c(), p.n))) {
            J j = p.l.l.x.s;
            Intrinsics.d(j);
            j.r.f();
            LinkedHashMap linkedHashMap2 = p.n;
            if (linkedHashMap2 == null) {
                linkedHashMap2 = new LinkedHashMap();
                p.n = linkedHashMap2;
            }
            linkedHashMap2.clear();
            linkedHashMap2.putAll(l.c());
        }
        p.p = l;
    }

    @Override // androidx.compose.ui.node.O
    public final O B0() {
        a0 a0Var = this.l.m;
        if (a0Var != null) {
            return a0Var.U0();
        }
        return null;
    }

    @Override // androidx.compose.ui.node.O
    public final androidx.compose.ui.layout.r C0() {
        return this.o;
    }

    @Override // androidx.compose.ui.node.O
    public final boolean D0() {
        return this.p != null;
    }

    @Override // androidx.compose.ui.node.O
    public final E E0() {
        return this.l.l;
    }

    @Override // androidx.compose.ui.node.O
    public final androidx.compose.ui.layout.L F0() {
        androidx.compose.ui.layout.L l = this.p;
        if (l != null) {
            return l;
        }
        throw new IllegalStateException("LookaheadDelegate has not been measured yet when measureResult is requested.");
    }

    @Override // androidx.compose.ui.layout.W, androidx.compose.ui.layout.J
    public final Object G() {
        return this.l.G();
    }

    @Override // androidx.compose.ui.node.O
    public final O G0() {
        a0 a0Var = this.l.n;
        if (a0Var != null) {
            return a0Var.U0();
        }
        return null;
    }

    @Override // androidx.compose.ui.node.O
    public final long H0() {
        return this.m;
    }

    @Override // androidx.compose.ui.node.O
    public final void J0() {
        s0(this.m, DefinitionKt.NO_Float_VALUE, null);
    }

    public void L0() {
        F0().d();
    }

    public final void M0(long j) {
        if (!androidx.compose.ui.unit.h.b(this.m, j)) {
            this.m = j;
            a0 a0Var = this.l;
            J j2 = a0Var.l.x.s;
            if (j2 != null) {
                j2.B0();
            }
            O.I0(a0Var);
        }
        if (this.h) {
            return;
        }
        A0(new k0(F0(), this));
    }

    public final long N0(P p, boolean z) {
        long jD = 0;
        P pU0 = this;
        while (!pU0.equals(p)) {
            if (!pU0.f || !z) {
                jD = androidx.compose.ui.unit.h.d(jD, pU0.m);
            }
            a0 a0Var = pU0.l.n;
            Intrinsics.d(a0Var);
            pU0 = a0Var.U0();
            Intrinsics.d(pU0);
        }
        return jD;
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.l.Z();
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.l.a();
    }

    @Override // androidx.compose.ui.node.O, androidx.compose.ui.layout.InterfaceC0894o
    public final boolean a0() {
        return true;
    }

    @Override // androidx.compose.ui.layout.InterfaceC0894o
    public final androidx.compose.ui.unit.k getLayoutDirection() {
        return this.l.l.s;
    }

    @Override // androidx.compose.ui.layout.W
    public final void s0(long j, float f, Function1 function1) {
        M0(j);
        if (this.g) {
            return;
        }
        L0();
    }
}
