package androidx.compose.ui.input.pointer;

import androidx.compose.foundation.C;
import androidx.compose.foundation.layout.Y;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0916l;
import androidx.compose.ui.node.l0;
import androidx.compose.ui.node.q0;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.L;
import kotlin.Unit;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.J;

/* loaded from: classes.dex */
public final class h extends androidx.compose.ui.p implements q0, l0, InterfaceC0916l {
    public C0878a n;
    public boolean o;

    @Override // androidx.compose.ui.node.l0
    public final void E(f fVar, g gVar, long j) {
        if (gVar == g.b) {
            int i = fVar.d;
            if (i == 4) {
                this.o = true;
                N0();
            } else if (i == 5) {
                O0();
            }
        }
    }

    @Override // androidx.compose.ui.node.l0
    public final void F() {
        O0();
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        O0();
    }

    public final void M0() {
        J j = new J();
        AbstractC0910f.y(this, new androidx.compose.ui.draganddrop.d(j, 1));
        h hVar = (h) j.a;
        C0878a c0878a = hVar != null ? hVar.n : this.n;
        k kVar = (k) AbstractC0910f.i(this, AbstractC0955m0.s);
        if (kVar != null) {
            L.a.a(((androidx.compose.ui.platform.r) kVar).a, c0878a);
        }
    }

    public final void N0() {
        F f = new F();
        f.a = true;
        AbstractC0910f.z(this, new C(f, 3));
        if (f.a) {
            M0();
        }
    }

    public final void O0() {
        Unit unit;
        k kVar;
        if (this.o) {
            this.o = false;
            if (this.m) {
                J j = new J();
                AbstractC0910f.y(this, new Y(j, 3));
                h hVar = (h) j.a;
                if (hVar != null) {
                    hVar.M0();
                    unit = Unit.a;
                } else {
                    unit = null;
                }
                if (unit != null || (kVar = (k) AbstractC0910f.i(this, AbstractC0955m0.s)) == null) {
                    return;
                }
                j.a.getClass();
                L.a.a(((androidx.compose.ui.platform.r) kVar).a, l.a);
            }
        }
    }

    @Override // androidx.compose.ui.node.q0
    public final /* bridge */ /* synthetic */ Object m() {
        return "androidx.compose.ui.input.pointer.PointerHoverIcon";
    }
}
