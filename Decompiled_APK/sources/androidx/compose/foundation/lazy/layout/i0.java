package androidx.compose.foundation.lazy.layout;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.runtime.C0775b0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class i0 extends androidx.compose.ui.p implements androidx.compose.ui.node.n0 {
    public kotlin.reflect.k n;
    public e0 o;
    public EnumC0320d0 p;
    public boolean q;
    public androidx.compose.ui.semantics.i r;
    public final g0 s = new g0(this, 0);
    public g0 t;

    public i0(kotlin.reflect.k kVar, e0 e0Var, EnumC0320d0 enumC0320d0, boolean z) {
        this.n = kVar;
        this.o = e0Var;
        this.p = enumC0320d0;
        this.q = z;
        M0();
    }

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    public final void M0() {
        this.r = new androidx.compose.ui.semantics.i(new f0(this, 1), new f0(this, 2));
        this.t = this.q ? new g0(this, 1) : null;
    }

    @Override // androidx.compose.ui.node.n0
    public final void r0(androidx.compose.ui.semantics.v vVar) {
        androidx.compose.ui.semantics.t.k(vVar);
        androidx.compose.ui.semantics.k kVar = (androidx.compose.ui.semantics.k) vVar;
        kVar.b(androidx.compose.ui.semantics.r.E, this.s);
        if (this.p == EnumC0320d0.a) {
            androidx.compose.ui.semantics.i iVar = this.r;
            if (iVar == null) {
                Intrinsics.m("scrollAxisRange");
                throw null;
            }
            androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.p;
            kotlin.reflect.n nVar = androidx.compose.ui.semantics.t.a[11];
            uVar.a(vVar, iVar);
        } else {
            androidx.compose.ui.semantics.i iVar2 = this.r;
            if (iVar2 == null) {
                Intrinsics.m("scrollAxisRange");
                throw null;
            }
            androidx.compose.ui.semantics.u uVar2 = androidx.compose.ui.semantics.r.o;
            kotlin.reflect.n nVar2 = androidx.compose.ui.semantics.t.a[10];
            uVar2.a(vVar, iVar2);
        }
        g0 g0Var = this.t;
        if (g0Var != null) {
            kVar.b(androidx.compose.ui.semantics.j.f, new androidx.compose.ui.semantics.a(null, g0Var));
        }
        kVar.b(androidx.compose.ui.semantics.j.A, new androidx.compose.ui.semantics.a(null, new C0775b0(new f0(this, 0), 24)));
        androidx.compose.ui.semantics.b bVarF = this.o.f();
        androidx.compose.ui.semantics.u uVar3 = androidx.compose.ui.semantics.r.f;
        kotlin.reflect.n nVar3 = androidx.compose.ui.semantics.t.a[20];
        uVar3.a(vVar, bVarF);
    }
}
