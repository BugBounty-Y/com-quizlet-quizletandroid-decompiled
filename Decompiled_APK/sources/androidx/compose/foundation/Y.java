package androidx.compose.foundation;

import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0920p;

/* loaded from: classes.dex */
public final class Y extends androidx.compose.ui.p implements androidx.compose.ui.node.q0, InterfaceC0920p {
    public static final z0 p = new z0(5);
    public boolean n;
    public androidx.compose.ui.node.a0 o;

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    public final Z M0() {
        if (!this.m) {
            return null;
        }
        androidx.compose.ui.node.q0 q0VarJ = AbstractC0910f.j(this, Z.o);
        if (q0VarJ instanceof Z) {
            return (Z) q0VarJ;
        }
        return null;
    }

    @Override // androidx.compose.ui.node.q0
    public final Object m() {
        return p;
    }

    @Override // androidx.compose.ui.node.InterfaceC0920p
    public final void y0(androidx.compose.ui.node.a0 a0Var) {
        Z zM0;
        this.o = a0Var;
        if (this.n) {
            if (!a0Var.W0().m) {
                Z zM02 = M0();
                if (zM02 != null) {
                    zM02.M0(null);
                    return;
                }
                return;
            }
            androidx.compose.ui.node.a0 a0Var2 = this.o;
            if (a0Var2 == null || !a0Var2.W0().m || (zM0 = M0()) == null) {
                return;
            }
            zM0.M0(this.o);
        }
    }
}
