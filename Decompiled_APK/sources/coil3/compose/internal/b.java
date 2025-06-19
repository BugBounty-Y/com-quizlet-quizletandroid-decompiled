package coil3.compose.internal;

import androidx.appcompat.app.L;
import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.layout.InterfaceC0889j;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.layout.W;
import androidx.compose.ui.layout.a0;
import androidx.compose.ui.node.G;
import androidx.compose.ui.node.InterfaceC0919o;
import androidx.compose.ui.node.InterfaceC0926w;
import androidx.compose.ui.node.O;
import androidx.compose.ui.node.n0;
import androidx.compose.ui.p;
import androidx.compose.ui.semantics.t;
import androidx.compose.ui.semantics.v;
import coil3.compose.h;
import coil3.compose.j;
import coil3.compose.n;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.collections.V;
import kotlin.ranges.l;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes.dex */
public final class b extends p implements InterfaceC0919o, InterfaceC0926w, n0 {
    public androidx.compose.ui.d n;
    public InterfaceC0889j o;
    public AbstractC0874w q;
    public String s;
    public coil3.compose.p t;
    public final j u;
    public float p = 1.0f;
    public boolean r = true;

    public b(j jVar, androidx.compose.ui.d dVar, InterfaceC0889j interfaceC0889j, AbstractC0874w abstractC0874w, String str, coil3.compose.p pVar) {
        this.n = dVar;
        this.o = interfaceC0889j;
        this.q = abstractC0874w;
        this.s = str;
        this.t = pVar;
        this.u = jVar;
    }

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        C cA0 = A0();
        j jVar = this.u;
        jVar.l = cA0;
        jVar.d();
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        this.u.b();
    }

    @Override // androidx.compose.ui.p
    public final void G0() {
        this.u.m(null);
    }

    public final long M0(long j) {
        if (androidx.compose.ui.geometry.e.e(j)) {
            return 0L;
        }
        long jH = this.u.h();
        if (jH == 9205357640488583168L) {
            return j;
        }
        float fD = androidx.compose.ui.geometry.e.d(jH);
        if (Float.isInfinite(fD) || Float.isNaN(fD)) {
            fD = androidx.compose.ui.geometry.e.d(j);
        }
        float fB = androidx.compose.ui.geometry.e.b(jH);
        if (Float.isInfinite(fB) || Float.isNaN(fB)) {
            fB = androidx.compose.ui.geometry.e.b(j);
        }
        long jA = T4.a(fD, fB);
        long jA2 = this.o.a(jA, j);
        float fA = a0.a(jA2);
        if (Float.isInfinite(fA) || Float.isNaN(fA)) {
            return j;
        }
        float fB2 = a0.b(jA2);
        return (Float.isInfinite(fB2) || Float.isNaN(fB2)) ? j : AbstractC0897s.n(jA, jA2);
    }

    public final long N0(long j) {
        float fJ;
        int i;
        float fB;
        boolean zF = androidx.compose.ui.unit.a.f(j);
        boolean zE = androidx.compose.ui.unit.a.e(j);
        if (zF && zE) {
            return j;
        }
        boolean z = androidx.compose.ui.unit.a.d(j) && androidx.compose.ui.unit.a.c(j);
        j jVar = this.u;
        long jH = jVar.h();
        if (jH == 9205357640488583168L) {
            return (!z || ((h) ((s0) jVar.u.a).getValue()).a() == null) ? j : androidx.compose.ui.unit.a.a(j, androidx.compose.ui.unit.a.h(j), 0, androidx.compose.ui.unit.a.g(j), 0, 10);
        }
        if (z && (zF || zE)) {
            fJ = androidx.compose.ui.unit.a.h(j);
            i = androidx.compose.ui.unit.a.g(j);
        } else {
            float fD = androidx.compose.ui.geometry.e.d(jH);
            float fB2 = androidx.compose.ui.geometry.e.b(jH);
            if (Float.isInfinite(fD) || Float.isNaN(fD)) {
                fJ = androidx.compose.ui.unit.a.j(j);
            } else {
                int i2 = g.b;
                fJ = l.b(fD, androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.h(j));
            }
            if (!Float.isInfinite(fB2) && !Float.isNaN(fB2)) {
                int i3 = g.b;
                fB = l.b(fB2, androidx.compose.ui.unit.a.i(j), androidx.compose.ui.unit.a.g(j));
                long jM0 = M0(T4.a(fJ, fB));
                return androidx.compose.ui.unit.a.a(j, L5.l(kotlin.math.c.b(androidx.compose.ui.geometry.e.d(jM0)), j), 0, L5.k(kotlin.math.c.b(androidx.compose.ui.geometry.e.b(jM0)), j), 0, 10);
            }
            i = androidx.compose.ui.unit.a.i(j);
        }
        fB = i;
        long jM02 = M0(T4.a(fJ, fB));
        return androidx.compose.ui.unit.a.a(j, L5.l(kotlin.math.c.b(androidx.compose.ui.geometry.e.d(jM02)), j), 0, L5.k(kotlin.math.c.b(androidx.compose.ui.geometry.e.b(jM02)), j), 0, 10);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int b(O o, J j, int i) {
        long jB = L5.b(0, i, 7);
        coil3.compose.p pVar = this.t;
        if (pVar != null) {
            pVar.n(jB);
        }
        if (this.u.h() == 9205357640488583168L) {
            return j.z(i);
        }
        long jN0 = N0(jB);
        return Math.max(androidx.compose.ui.unit.a.j(jN0), j.z(i));
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int c(O o, J j, int i) {
        long jB = L5.b(0, i, 7);
        coil3.compose.p pVar = this.t;
        if (pVar != null) {
            pVar.n(jB);
        }
        if (this.u.h() == 9205357640488583168L) {
            return j.x(i);
        }
        long jN0 = N0(jB);
        return Math.max(androidx.compose.ui.unit.a.j(jN0), j.x(i));
    }

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(G g) {
        androidx.compose.ui.graphics.drawscope.b bVar = g.a;
        long jM0 = M0(bVar.g());
        androidx.compose.ui.d dVar = this.n;
        int i = g.b;
        long jA = R5.a(kotlin.math.c.b(androidx.compose.ui.geometry.e.d(jM0)), kotlin.math.c.b(androidx.compose.ui.geometry.e.b(jM0)));
        long jG = bVar.g();
        long jA2 = dVar.a(jA, R5.a(kotlin.math.c.b(androidx.compose.ui.geometry.e.d(jG)), kotlin.math.c.b(androidx.compose.ui.geometry.e.b(jG))), g.getLayoutDirection());
        int i2 = (int) (jA2 >> 32);
        int i3 = (int) (jA2 & 4294967295L);
        com.quizlet.data.repository.folderset.c cVar = bVar.b;
        long jR = cVar.r();
        cVar.o().e();
        try {
            L l = (L) cVar.b;
            com.quizlet.data.repository.folderset.c cVar2 = (com.quizlet.data.repository.folderset.c) l.b;
            if (this.r) {
                l.H(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, androidx.compose.ui.geometry.e.d(cVar2.r()), androidx.compose.ui.geometry.e.b(cVar2.r()), 1);
            }
            l.S(i2, i3);
            this.u.g(g, jM0, this.p, this.q);
            cVar.o().q();
            cVar.y(jR);
            g.b();
        } catch (Throwable th) {
            d0.y(cVar, jR);
            throw th;
        }
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int f(O o, J j, int i) {
        long jB = L5.b(i, 0, 13);
        coil3.compose.p pVar = this.t;
        if (pVar != null) {
            pVar.n(jB);
        }
        if (this.u.h() == 9205357640488583168L) {
            return j.X(i);
        }
        long jN0 = N0(jB);
        return Math.max(androidx.compose.ui.unit.a.i(jN0), j.X(i));
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(M m, J j, long j2) {
        coil3.compose.p pVar = this.t;
        if (pVar != null) {
            pVar.n(j2);
        }
        W wB = j.B(N0(j2));
        return m.n0(wB.a, wB.b, V.c(), new n(wB, 1));
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int i(O o, J j, int i) {
        long jB = L5.b(i, 0, 13);
        coil3.compose.p pVar = this.t;
        if (pVar != null) {
            pVar.n(jB);
        }
        if (this.u.h() == 9205357640488583168L) {
            return j.b(i);
        }
        long jN0 = N0(jB);
        return Math.max(androidx.compose.ui.unit.a.i(jN0), j.b(i));
    }

    @Override // androidx.compose.ui.node.n0
    public final void r0(v vVar) {
        String str = this.s;
        if (str != null) {
            t.e(vVar, str);
            t.h(vVar, 5);
        }
    }
}
