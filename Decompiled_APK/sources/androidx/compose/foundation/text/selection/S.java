package androidx.compose.foundation.text.selection;

import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.K0;
import androidx.compose.foundation.text.u0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class S implements u0 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;

    public S(i0 i0Var, boolean z) {
        this.c = i0Var;
        this.b = z;
    }

    private final void e() {
    }

    private final void f(long j) {
    }

    @Override // androidx.compose.foundation.text.u0
    public final void a(long j) {
        switch (this.a) {
            case 0:
                U u = (U) this.c;
                if (u.c() == null) {
                    return;
                }
                C0536q c0536qE = u.e();
                Intrinsics.d(c0536qE);
                boolean z = this.b;
                Object objD = u.a.c.d((z ? c0536qE.a : c0536qE.b).c);
                if (objD == null) {
                    throw new IllegalStateException("SelectionRegistrar should contain the current selection's selectableIds");
                }
                C0532m c0532m = (C0532m) objD;
                androidx.compose.ui.layout.r rVarC = c0532m.c();
                if (rVarC == null) {
                    throw new IllegalStateException("Current selectable should have layout coordinates.");
                }
                long jA = c0532m.a(c0536qE, z);
                if (Q4.i(jA)) {
                    return;
                }
                ((L0) u.l).setValue(new androidx.compose.ui.geometry.b(u.j().f(rVarC, H.a(jA))));
                ((L0) u.m).setValue(new androidx.compose.ui.geometry.b(0L));
                return;
            default:
                return;
        }
    }

    @Override // androidx.compose.foundation.text.u0
    public final void b() {
        switch (this.a) {
            case 0:
                U u = (U) this.c;
                u.n(true);
                ((L0) u.p).setValue(null);
                ((L0) u.q).setValue(null);
                break;
            default:
                i0 i0Var = (i0) this.c;
                i0.b(i0Var, null);
                i0.a(i0Var, null);
                i0Var.r(true);
                break;
        }
    }

    @Override // androidx.compose.foundation.text.u0
    public final void c() {
        C0536q c0536qE;
        androidx.compose.ui.layout.r rVarC;
        K0 k0D;
        switch (this.a) {
            case 0:
                U u = (U) this.c;
                boolean z = this.b;
                if ((z ? (androidx.compose.ui.geometry.b) ((L0) u.n).getValue() : (androidx.compose.ui.geometry.b) ((L0) u.o).getValue()) != null && (c0536qE = u.e()) != null) {
                    C0532m c0532m = (C0532m) u.a.c.d((z ? c0536qE.a : c0536qE.b).c);
                    if (c0532m != null && (rVarC = c0532m.c()) != null) {
                        long jA = c0532m.a(c0536qE, z);
                        if (!Q4.i(jA)) {
                            ((L0) u.q).setValue(new androidx.compose.ui.geometry.b(u.j().f(rVarC, H.a(jA))));
                            ((L0) u.p).setValue(z ? androidx.compose.foundation.text.U.b : androidx.compose.foundation.text.U.c);
                            u.n(false);
                            break;
                        }
                    }
                }
                break;
            default:
                boolean z2 = this.b;
                androidx.compose.foundation.text.U u2 = z2 ? androidx.compose.foundation.text.U.b : androidx.compose.foundation.text.U.c;
                i0 i0Var = (i0) this.c;
                ((L0) i0Var.p).setValue(u2);
                long jA2 = H.a(i0Var.k(z2));
                C0492h0 c0492h0 = i0Var.d;
                if (c0492h0 != null && (k0D = c0492h0.d()) != null) {
                    long jE = k0D.e(jA2);
                    i0Var.m = jE;
                    ((L0) i0Var.q).setValue(new androidx.compose.ui.geometry.b(jE));
                    i0Var.o = 0L;
                    i0Var.r = -1;
                    C0492h0 c0492h02 = i0Var.d;
                    if (c0492h02 != null) {
                        ((L0) c0492h02.q).setValue(Boolean.TRUE);
                    }
                    i0Var.r(false);
                    break;
                }
                break;
        }
    }

    @Override // androidx.compose.foundation.text.u0
    public final void d(long j) {
        switch (this.a) {
            case 0:
                U u = (U) this.c;
                if (u.c() != null) {
                    InterfaceC0773a0 interfaceC0773a0 = u.m;
                    ((L0) interfaceC0773a0).setValue(new androidx.compose.ui.geometry.b(androidx.compose.ui.geometry.b.h(((androidx.compose.ui.geometry.b) ((L0) interfaceC0773a0).getValue()).a, j)));
                    InterfaceC0773a0 interfaceC0773a02 = u.l;
                    long jH = androidx.compose.ui.geometry.b.h(((androidx.compose.ui.geometry.b) ((L0) interfaceC0773a02).getValue()).a, ((androidx.compose.ui.geometry.b) ((L0) interfaceC0773a0).getValue()).a);
                    if (u.p(jH, ((androidx.compose.ui.geometry.b) ((L0) interfaceC0773a02).getValue()).a, this.b, C0537s.g)) {
                        ((L0) interfaceC0773a02).setValue(new androidx.compose.ui.geometry.b(jH));
                        ((L0) interfaceC0773a0).setValue(new androidx.compose.ui.geometry.b(0L));
                        break;
                    }
                }
                break;
            default:
                i0 i0Var = (i0) this.c;
                long jH2 = androidx.compose.ui.geometry.b.h(i0Var.o, j);
                i0Var.o = jH2;
                ((L0) i0Var.q).setValue(new androidx.compose.ui.geometry.b(androidx.compose.ui.geometry.b.h(i0Var.m, jH2)));
                androidx.compose.ui.text.input.A aL = i0Var.l();
                androidx.compose.ui.geometry.b bVarI = i0Var.i();
                Intrinsics.d(bVarI);
                r rVar = C0537s.g;
                i0.c(i0Var, aL, bVarI.a, false, this.b, rVar, true);
                i0Var.r(false);
                break;
        }
    }

    @Override // androidx.compose.foundation.text.u0
    public final void onCancel() {
        switch (this.a) {
            case 0:
                U u = (U) this.c;
                u.n(true);
                ((L0) u.p).setValue(null);
                ((L0) u.q).setValue(null);
                break;
        }
    }

    @Override // androidx.compose.foundation.text.u0
    public final void onStop() {
        switch (this.a) {
            case 0:
                U u = (U) this.c;
                u.n(true);
                ((L0) u.p).setValue(null);
                ((L0) u.q).setValue(null);
                break;
            default:
                i0 i0Var = (i0) this.c;
                i0.b(i0Var, null);
                i0.a(i0Var, null);
                i0Var.r(true);
                break;
        }
    }

    public S(boolean z, U u) {
        this.b = z;
        this.c = u;
    }
}
