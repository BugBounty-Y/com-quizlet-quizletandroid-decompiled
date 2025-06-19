package androidx.compose.animation;

import androidx.compose.animation.core.C0272v0;
import androidx.compose.animation.core.E0;
import androidx.compose.animation.core.w0;
import androidx.compose.runtime.L0;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class Z extends h0 {
    public E0 o;
    public w0 p;
    public w0 q;
    public w0 r;
    public a0 s;
    public b0 t;
    public Function0 u;
    public P v;
    public long w;
    public androidx.compose.ui.d x;
    public final Y y;
    public final Y z;

    public Z(E0 e0, w0 w0Var, w0 w0Var2, w0 w0Var3, a0 a0Var, b0 b0Var, Function0 function0, P p) {
        super(0);
        this.o = e0;
        this.p = w0Var;
        this.q = w0Var2;
        this.r = w0Var3;
        this.s = a0Var;
        this.t = b0Var;
        this.u = function0;
        this.v = p;
        this.w = H.a;
        L5.b(0, 0, 15);
        this.y = new Y(this, 0);
        this.z = new Y(this, 1);
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        this.w = H.a;
    }

    public final androidx.compose.ui.d O0() {
        if (this.o.f().b(O.a, O.b)) {
            I i = this.s.a.c;
            if (i != null) {
                return i.a;
            }
            I i2 = this.t.a.c;
            if (i2 != null) {
                return i2.a;
            }
            return null;
        }
        I i3 = this.t.a.c;
        if (i3 != null) {
            return i3.a;
        }
        I i4 = this.s.a.c;
        if (i4 != null) {
            return i4.a;
        }
        return null;
    }

    @Override // androidx.compose.animation.h0, androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        Object obj = null;
        if (this.o.a.t() == ((L0) this.o.d).getValue()) {
            this.x = null;
        } else if (this.x == null) {
            androidx.compose.ui.d dVarO0 = O0();
            if (dVarO0 == null) {
                dVarO0 = androidx.compose.ui.b.a;
            }
            this.x = dVarO0;
        }
        if (m.a0()) {
            androidx.compose.ui.layout.W wB = j.B(j2);
            long jA = R5.a(wB.a, wB.b);
            this.w = jA;
            return m.n0((int) (jA >> 32), (int) (jA & 4294967295L), kotlin.collections.V.c(), new C(wB, 1));
        }
        if (!((Boolean) this.u.invoke()).booleanValue()) {
            androidx.compose.ui.layout.W wB2 = j.B(j2);
            return m.n0(wB2.a, wB2.b, kotlin.collections.V.c(), new C(wB2, 2));
        }
        P p = this.v;
        w0 w0Var = p.a;
        a0 a0Var = p.d;
        b0 b0Var = p.e;
        C0272v0 c0272v0A = w0Var != null ? w0Var.a(new Q(a0Var, b0Var, 0), new Q(a0Var, b0Var, 1)) : null;
        w0 w0Var2 = p.b;
        C0272v0 c0272v0A2 = w0Var2 != null ? w0Var2.a(new Q(a0Var, b0Var, 2), new Q(a0Var, b0Var, 3)) : null;
        if (p.c.a.t() == O.a) {
            q0 q0Var = b0Var.a;
        } else {
            q0 q0Var2 = b0Var.a;
        }
        w0 w0Var3 = p.f;
        androidx.activity.compose.g gVar = new androidx.activity.compose.g(c0272v0A, c0272v0A2, w0Var3 != null ? w0Var3.a(C0229c.k, new androidx.activity.compose.g(obj, a0Var, b0Var, 4)) : null, 3);
        androidx.compose.ui.layout.W wB3 = j.B(j2);
        long jA2 = R5.a(wB3.a, wB3.b);
        long j3 = !androidx.compose.ui.unit.j.a(this.w, H.a) ? this.w : jA2;
        w0 w0Var4 = this.p;
        C0272v0 c0272v0A3 = w0Var4 != null ? w0Var4.a(this.y, new X(this, j3, 0)) : null;
        if (c0272v0A3 != null) {
            jA2 = ((androidx.compose.ui.unit.j) c0272v0A3.getValue()).a;
        }
        long jI = L5.i(j2, jA2);
        w0 w0Var5 = this.q;
        long j4 = w0Var5 != null ? ((androidx.compose.ui.unit.h) w0Var5.a(C0229c.o, new X(this, j3, 1)).getValue()).a : 0L;
        w0 w0Var6 = this.r;
        long j5 = w0Var6 != null ? ((androidx.compose.ui.unit.h) w0Var6.a(this.z, new X(this, j3, 2)).getValue()).a : 0L;
        androidx.compose.ui.d dVar = this.x;
        return m.n0((int) (jI >> 32), (int) (jI & 4294967295L), kotlin.collections.V.c(), new W(wB3, androidx.compose.ui.unit.h.d(dVar != null ? dVar.a(j3, jI, androidx.compose.ui.unit.k.a) : 0L, j5), j4, gVar, 0));
    }
}
