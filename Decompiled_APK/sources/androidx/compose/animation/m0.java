package androidx.compose.animation;

import androidx.compose.animation.core.C0238e;
import androidx.compose.animation.core.InterfaceC0256n;
import androidx.compose.animation.core.M0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;

/* loaded from: classes.dex */
public final class m0 extends h0 {
    public InterfaceC0256n o;
    public long p;
    public long q;
    public boolean r;
    public final InterfaceC0773a0 s;

    public m0(InterfaceC0256n interfaceC0256n) {
        super(0);
        this.o = interfaceC0256n;
        this.p = H.a;
        this.q = L5.b(0, 0, 15);
        this.s = C0776c.z(null);
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        this.p = H.a;
        this.r = false;
    }

    @Override // androidx.compose.ui.p
    public final void G0() {
        ((L0) this.s).setValue(null);
    }

    @Override // androidx.compose.animation.h0, androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        androidx.compose.ui.layout.W wB;
        j0 j0Var;
        long jI;
        j0 j0Var2;
        if (m.a0()) {
            this.q = j2;
            this.r = true;
            wB = j.B(j2);
        } else {
            wB = j.B(this.r ? this.q : j2);
        }
        androidx.compose.ui.layout.W w = wB;
        long jA = R5.a(w.a, w.b);
        if (m.a0()) {
            this.p = jA;
            jI = jA;
        } else {
            long j3 = !androidx.compose.ui.unit.j.a(this.p, H.a) ? this.p : jA;
            InterfaceC0773a0 interfaceC0773a0 = this.s;
            j0 j0Var3 = (j0) ((L0) interfaceC0773a0).getValue();
            if (j0Var3 != null) {
                C0238e c0238e = j0Var3.a;
                boolean z = (androidx.compose.ui.unit.j.a(j3, ((androidx.compose.ui.unit.j) c0238e.d()).a) || c0238e.e()) ? false : true;
                if (!androidx.compose.ui.unit.j.a(j3, ((androidx.compose.ui.unit.j) ((L0) c0238e.e).getValue()).a) || z) {
                    j0Var3.b = ((androidx.compose.ui.unit.j) c0238e.d()).a;
                    j0Var2 = j0Var3;
                    kotlinx.coroutines.E.A(A0(), null, null, new k0(j0Var2, j3, this, null), 3);
                } else {
                    j0Var2 = j0Var3;
                }
                j0Var = j0Var2;
            } else {
                j0Var = new j0(new C0238e(new androidx.compose.ui.unit.j(j3), M0.h, new androidx.compose.ui.unit.j(R5.a(1, 1)), 8), j3);
            }
            ((L0) interfaceC0773a0).setValue(j0Var);
            jI = L5.i(j2, ((androidx.compose.ui.unit.j) j0Var.a.d()).a);
        }
        int i = (int) (jI >> 32);
        int i2 = (int) (jI & 4294967295L);
        return m.n0(i, i2, kotlin.collections.V.c(), new l0(this, jA, i, i2, m, w));
    }
}
