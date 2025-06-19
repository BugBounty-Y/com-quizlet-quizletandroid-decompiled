package androidx.compose.ui.draw;

import androidx.appcompat.app.L;
import androidx.compose.animation.C;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.layout.InterfaceC0889j;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.layout.W;
import androidx.compose.ui.node.G;
import androidx.compose.ui.node.InterfaceC0919o;
import androidx.compose.ui.node.InterfaceC0926w;
import androidx.compose.ui.node.O;
import androidx.compose.ui.p;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.collections.V;

/* loaded from: classes.dex */
public final class j extends p implements InterfaceC0926w, InterfaceC0919o {
    public androidx.compose.ui.graphics.painter.b n;
    public boolean o;
    public androidx.compose.ui.d p;
    public InterfaceC0889j q;
    public float r;
    public AbstractC0874w s;

    public static boolean N0(long j) {
        if (androidx.compose.ui.geometry.e.a(j, 9205357640488583168L)) {
            return false;
        }
        float fB = androidx.compose.ui.geometry.e.b(j);
        return (Float.isInfinite(fB) || Float.isNaN(fB)) ? false : true;
    }

    public static boolean O0(long j) {
        if (androidx.compose.ui.geometry.e.a(j, 9205357640488583168L)) {
            return false;
        }
        float fD = androidx.compose.ui.geometry.e.d(j);
        return (Float.isInfinite(fD) || Float.isNaN(fD)) ? false : true;
    }

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    public final boolean M0() {
        return this.o && this.n.h() != 9205357640488583168L;
    }

    public final long P0(long j) {
        boolean z = false;
        boolean z2 = androidx.compose.ui.unit.a.d(j) && androidx.compose.ui.unit.a.c(j);
        if (androidx.compose.ui.unit.a.f(j) && androidx.compose.ui.unit.a.e(j)) {
            z = true;
        }
        if ((!M0() && z2) || z) {
            return androidx.compose.ui.unit.a.a(j, androidx.compose.ui.unit.a.h(j), 0, androidx.compose.ui.unit.a.g(j), 0, 10);
        }
        long jH = this.n.h();
        long jA = T4.a(L5.l(O0(jH) ? Math.round(androidx.compose.ui.geometry.e.d(jH)) : androidx.compose.ui.unit.a.j(j), j), L5.k(N0(jH) ? Math.round(androidx.compose.ui.geometry.e.b(jH)) : androidx.compose.ui.unit.a.i(j), j));
        if (M0()) {
            long jA2 = T4.a(!O0(this.n.h()) ? androidx.compose.ui.geometry.e.d(jA) : androidx.compose.ui.geometry.e.d(this.n.h()), !N0(this.n.h()) ? androidx.compose.ui.geometry.e.b(jA) : androidx.compose.ui.geometry.e.b(this.n.h()));
            jA = (androidx.compose.ui.geometry.e.d(jA) == DefinitionKt.NO_Float_VALUE || androidx.compose.ui.geometry.e.b(jA) == DefinitionKt.NO_Float_VALUE) ? 0L : AbstractC0897s.n(jA2, this.q.a(jA2, jA));
        }
        return androidx.compose.ui.unit.a.a(j, L5.l(Math.round(androidx.compose.ui.geometry.e.d(jA)), j), 0, L5.k(Math.round(androidx.compose.ui.geometry.e.b(jA)), j), 0, 10);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int b(O o, J j, int i) {
        if (!M0()) {
            return j.z(i);
        }
        long jP0 = P0(L5.b(0, i, 7));
        return Math.max(androidx.compose.ui.unit.a.j(jP0), j.z(i));
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int c(O o, J j, int i) {
        if (!M0()) {
            return j.x(i);
        }
        long jP0 = P0(L5.b(0, i, 7));
        return Math.max(androidx.compose.ui.unit.a.j(jP0), j.x(i));
    }

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(G g) {
        long jH = this.n.h();
        boolean zO0 = O0(jH);
        androidx.compose.ui.graphics.drawscope.b bVar = g.a;
        long jA = T4.a(zO0 ? androidx.compose.ui.geometry.e.d(jH) : androidx.compose.ui.geometry.e.d(bVar.g()), N0(jH) ? androidx.compose.ui.geometry.e.b(jH) : androidx.compose.ui.geometry.e.b(bVar.g()));
        long jN = (androidx.compose.ui.geometry.e.d(bVar.g()) == DefinitionKt.NO_Float_VALUE || androidx.compose.ui.geometry.e.b(bVar.g()) == DefinitionKt.NO_Float_VALUE) ? 0L : AbstractC0897s.n(jA, this.q.a(jA, bVar.g()));
        long jA2 = this.p.a(R5.a(Math.round(androidx.compose.ui.geometry.e.d(jN)), Math.round(androidx.compose.ui.geometry.e.b(jN))), R5.a(Math.round(androidx.compose.ui.geometry.e.d(bVar.g())), Math.round(androidx.compose.ui.geometry.e.b(bVar.g()))), g.getLayoutDirection());
        float f = (int) (jA2 >> 32);
        float f2 = (int) (jA2 & 4294967295L);
        ((L) bVar.b.b).S(f, f2);
        try {
            this.n.g(g, jN, this.r, this.s);
            ((L) bVar.b.b).S(-f, -f2);
            g.b();
        } catch (Throwable th) {
            ((L) bVar.b.b).S(-f, -f2);
            throw th;
        }
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int f(O o, J j, int i) {
        if (!M0()) {
            return j.X(i);
        }
        long jP0 = P0(L5.b(i, 0, 13));
        return Math.max(androidx.compose.ui.unit.a.i(jP0), j.X(i));
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(M m, J j, long j2) {
        W wB = j.B(P0(j2));
        return m.n0(wB.a, wB.b, V.c(), new C(wB, 13));
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int i(O o, J j, int i) {
        if (!M0()) {
            return j.b(i);
        }
        long jP0 = P0(L5.b(i, 0, 13));
        return Math.max(androidx.compose.ui.unit.a.i(jP0), j.b(i));
    }

    public final String toString() {
        return "PainterModifier(painter=" + this.n + ", sizeToIntrinsics=" + this.o + ", alignment=" + this.p + ", alpha=" + this.r + ", colorFilter=" + this.s + ')';
    }
}
