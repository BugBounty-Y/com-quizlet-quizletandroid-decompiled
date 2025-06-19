package androidx.compose.foundation;

import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0919o;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class r extends androidx.compose.ui.p implements InterfaceC0919o, androidx.compose.ui.node.c0 {
    public long n;
    public AbstractC0857q o;
    public float p;
    public androidx.compose.ui.graphics.V q;
    public long r;
    public androidx.compose.ui.unit.k s;
    public androidx.compose.ui.graphics.N t;
    public androidx.compose.ui.graphics.V u;

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(androidx.compose.ui.node.G g) {
        C0850j c0850j;
        if (this.q == androidx.compose.ui.graphics.F.a) {
            if (!C0861v.c(this.n, C0861v.g)) {
                androidx.compose.ui.graphics.drawscope.d.I(g, this.n, 0L, 0L, DefinitionKt.NO_Float_VALUE, 126);
            }
            AbstractC0857q abstractC0857q = this.o;
            if (abstractC0857q != null) {
                androidx.compose.ui.graphics.drawscope.d.J(g, abstractC0857q, 0L, 0L, this.p, null, 118);
            }
        } else {
            kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
            androidx.compose.ui.graphics.drawscope.b bVar = g.a;
            if (androidx.compose.ui.geometry.e.a(bVar.g(), this.r) && g.getLayoutDirection() == this.s && Intrinsics.b(this.u, this.q)) {
                androidx.compose.ui.graphics.N n = this.t;
                Intrinsics.d(n);
                j.a = n;
            } else {
                AbstractC0910f.s(this, new C0473q(j, this, g, 0));
            }
            this.t = (androidx.compose.ui.graphics.N) j.a;
            this.r = bVar.g();
            this.s = g.getLayoutDirection();
            this.u = this.q;
            Object obj = j.a;
            Intrinsics.d(obj);
            androidx.compose.ui.graphics.N n2 = (androidx.compose.ui.graphics.N) obj;
            if (!C0861v.c(this.n, C0861v.g)) {
                androidx.compose.ui.graphics.F.n(g, n2, this.n);
            }
            AbstractC0857q abstractC0857q2 = this.o;
            if (abstractC0857q2 != null) {
                float f = this.p;
                androidx.compose.ui.graphics.drawscope.g gVar = androidx.compose.ui.graphics.drawscope.g.a;
                if (n2 instanceof androidx.compose.ui.graphics.L) {
                    androidx.compose.ui.geometry.c cVar = ((androidx.compose.ui.graphics.L) n2).a;
                    g.h0(abstractC0857q2, Q4.c(cVar.a, cVar.b), T4.a(cVar.e(), cVar.d()), f, gVar, 3);
                } else {
                    if (n2 instanceof androidx.compose.ui.graphics.M) {
                        androidx.compose.ui.graphics.M m = (androidx.compose.ui.graphics.M) n2;
                        c0850j = m.b;
                        if (c0850j == null) {
                            androidx.compose.ui.geometry.d dVar = m.a;
                            float fB = androidx.compose.ui.geometry.a.b(dVar.h);
                            g.d(abstractC0857q2, Q4.c(dVar.a, dVar.b), T4.a(dVar.b(), dVar.a()), O4.a(fB, fB), f, gVar);
                        }
                    } else {
                        if (!(n2 instanceof androidx.compose.ui.graphics.K)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        c0850j = ((androidx.compose.ui.graphics.K) n2).a;
                    }
                    g.l0(c0850j, abstractC0857q2, f, gVar, 3);
                }
            }
        }
        g.b();
    }

    @Override // androidx.compose.ui.node.c0
    public final void k0() {
        this.r = 9205357640488583168L;
        this.s = null;
        this.t = null;
        this.u = null;
        AbstractC0910f.n(this);
    }
}
