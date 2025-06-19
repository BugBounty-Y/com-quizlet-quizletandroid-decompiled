package androidx.compose.foundation;

import android.view.View;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0919o;
import androidx.compose.ui.node.InterfaceC0920p;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class s0 extends androidx.compose.ui.p implements InterfaceC0920p, InterfaceC0919o, androidx.compose.ui.node.n0, androidx.compose.ui.node.c0 {
    public kotlin.jvm.internal.r n;
    public kotlin.jvm.internal.r o;
    public E0 p;
    public View q;
    public androidx.compose.ui.unit.b r;
    public D0 s;
    public androidx.compose.runtime.E u;
    public androidx.compose.ui.unit.j w;
    public kotlinx.coroutines.channels.h x;
    public final InterfaceC0773a0 t = C0776c.y(null, androidx.compose.runtime.V.c);
    public long v = 9205357640488583168L;

    /* JADX WARN: Multi-variable type inference failed */
    public s0(Function1 function1, Function1 function12, E0 e0) {
        this.n = (kotlin.jvm.internal.r) function1;
        this.o = (kotlin.jvm.internal.r) function12;
        this.p = e0;
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        k0();
        this.x = D1.a(0, 7, null);
        kotlinx.coroutines.E.A(A0(), null, null, new r0(this, null), 3);
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        D0 d0 = this.s;
        if (d0 != null) {
            ((F0) d0).b();
        }
        this.s = null;
    }

    public final long M0() {
        if (this.u == null) {
            this.u = C0776c.q(new C0474q0(this, 0));
        }
        androidx.compose.runtime.E e = this.u;
        if (e != null) {
            return ((androidx.compose.ui.geometry.b) e.getValue()).a;
        }
        return 9205357640488583168L;
    }

    public final void N0() {
        D0 d0 = this.s;
        if (d0 != null) {
            ((F0) d0).b();
        }
        View viewX = this.q;
        if (viewX == null) {
            viewX = AbstractC0910f.x(this);
        }
        this.q = viewX;
        androidx.compose.ui.unit.b bVar = this.r;
        if (bVar == null) {
            bVar = AbstractC0910f.v(this).r;
        }
        this.r = bVar;
        this.s = this.p.b(viewX, bVar);
        P0();
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public final void O0() {
        androidx.compose.ui.unit.b bVar = this.r;
        if (bVar == null) {
            bVar = AbstractC0910f.v(this).r;
            this.r = bVar;
        }
        long j = ((androidx.compose.ui.geometry.b) this.n.invoke(bVar)).a;
        if (!Q4.h(j) || !Q4.h(M0())) {
            this.v = 9205357640488583168L;
            D0 d0 = this.s;
            if (d0 != null) {
                ((F0) d0).b();
                return;
            }
            return;
        }
        this.v = androidx.compose.ui.geometry.b.h(M0(), j);
        if (this.s == null) {
            N0();
        }
        D0 d02 = this.s;
        if (d02 != null) {
            d02.a(this.v, 9205357640488583168L);
        }
        P0();
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public final void P0() {
        androidx.compose.ui.unit.b bVar;
        D0 d0 = this.s;
        if (d0 == null || (bVar = this.r) == null) {
            return;
        }
        F0 f0 = (F0) d0;
        long jC = f0.c();
        androidx.compose.ui.unit.j jVar = this.w;
        if (jVar != null && jC == jVar.a) {
            return;
        }
        this.o.invoke(new androidx.compose.ui.unit.g(bVar.s(R5.f(f0.c()))));
        this.w = new androidx.compose.ui.unit.j(f0.c());
    }

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(androidx.compose.ui.node.G g) {
        g.b();
        kotlinx.coroutines.channels.h hVar = this.x;
        if (hVar != null) {
            hVar.o(Unit.a);
        }
    }

    @Override // androidx.compose.ui.node.c0
    public final void k0() {
        AbstractC0910f.s(this, new C0474q0(this, 2));
    }

    @Override // androidx.compose.ui.node.n0
    public final void r0(androidx.compose.ui.semantics.v vVar) {
        ((androidx.compose.ui.semantics.k) vVar).b(t0.a, new C0474q0(this, 1));
    }

    @Override // androidx.compose.ui.node.InterfaceC0920p
    public final void y0(androidx.compose.ui.node.a0 a0Var) {
        ((androidx.compose.runtime.L0) this.t).setValue(a0Var);
    }
}
