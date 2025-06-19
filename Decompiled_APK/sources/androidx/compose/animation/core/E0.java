package androidx.compose.animation.core;

import androidx.compose.animation.C0296x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class E0 {
    public final J0 a;
    public final E0 b;
    public final String c;
    public final InterfaceC0773a0 d;
    public final InterfaceC0773a0 e;
    public final androidx.compose.runtime.J0 f = C0776c.x(0);
    public final androidx.compose.runtime.J0 g = C0776c.x(Long.MIN_VALUE);
    public final InterfaceC0773a0 h;
    public final androidx.compose.runtime.snapshots.q i;
    public final androidx.compose.runtime.snapshots.q j;
    public final InterfaceC0773a0 k;
    public final androidx.compose.runtime.E l;

    public E0(J0 j0, E0 e0, String str) {
        this.a = j0;
        this.b = e0;
        this.c = str;
        this.d = C0776c.z(j0.t());
        this.e = C0776c.z(new y0(j0.t(), j0.t()));
        Boolean bool = Boolean.FALSE;
        this.h = C0776c.z(bool);
        this.i = new androidx.compose.runtime.snapshots.q();
        this.j = new androidx.compose.runtime.snapshots.q();
        this.k = C0776c.z(bool);
        this.l = C0776c.q(new C0296x(this, 1));
        j0.M(this);
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x008d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(java.lang.Object r10, androidx.compose.runtime.InterfaceC0806l r11, int r12) {
        /*
            Method dump skipped, instructions count: 234
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.core.E0.a(java.lang.Object, androidx.compose.runtime.l, int):void");
    }

    public final long b() {
        androidx.compose.runtime.snapshots.q qVar = this.i;
        int size = qVar.size();
        long jMax = 0;
        for (int i = 0; i < size; i++) {
            jMax = Math.max(jMax, ((z0) qVar.get(i)).l.i());
        }
        androidx.compose.runtime.snapshots.q qVar2 = this.j;
        int size2 = qVar2.size();
        for (int i2 = 0; i2 < size2; i2++) {
            jMax = Math.max(jMax, ((E0) qVar2.get(i2)).b());
        }
        return jMax;
    }

    public final void c() {
        androidx.compose.runtime.snapshots.q qVar = this.i;
        int size = qVar.size();
        for (int i = 0; i < size; i++) {
            z0 z0Var = (z0) qVar.get(i);
            z0Var.f = null;
            z0Var.e = null;
            z0Var.i = false;
        }
        androidx.compose.runtime.snapshots.q qVar2 = this.j;
        int size2 = qVar2.size();
        for (int i2 = 0; i2 < size2; i2++) {
            ((E0) qVar2.get(i2)).c();
        }
    }

    public final boolean d() {
        androidx.compose.runtime.snapshots.q qVar = this.i;
        int size = qVar.size();
        for (int i = 0; i < size; i++) {
            if (((z0) qVar.get(i)).e != null) {
                return true;
            }
        }
        androidx.compose.runtime.snapshots.q qVar2 = this.j;
        int size2 = qVar2.size();
        for (int i2 = 0; i2 < size2; i2++) {
            if (((E0) qVar2.get(i2)).d()) {
                return true;
            }
        }
        return false;
    }

    public final long e() {
        E0 e0 = this.b;
        return e0 != null ? e0.e() : this.f.i();
    }

    public final x0 f() {
        return (x0) ((androidx.compose.runtime.L0) this.e).getValue();
    }

    public final Object g() {
        return ((androidx.compose.runtime.L0) this.d).getValue();
    }

    public final boolean h() {
        return ((Boolean) ((androidx.compose.runtime.L0) this.k).getValue()).booleanValue();
    }

    public final void i(long j, boolean z) {
        androidx.compose.runtime.J0 j0 = this.g;
        long jI = j0.i();
        J0 j02 = this.a;
        if (jI == Long.MIN_VALUE) {
            j0.j(j);
            ((androidx.compose.runtime.L0) ((InterfaceC0773a0) j02.b)).setValue(Boolean.TRUE);
        } else if (!((Boolean) ((androidx.compose.runtime.L0) ((InterfaceC0773a0) j02.b)).getValue()).booleanValue()) {
            ((androidx.compose.runtime.L0) ((InterfaceC0773a0) j02.b)).setValue(Boolean.TRUE);
        }
        ((androidx.compose.runtime.L0) this.h).setValue(Boolean.FALSE);
        androidx.compose.runtime.snapshots.q qVar = this.i;
        int size = qVar.size();
        boolean z2 = true;
        for (int i = 0; i < size; i++) {
            z0 z0Var = (z0) qVar.get(i);
            boolean zBooleanValue = ((Boolean) ((androidx.compose.runtime.L0) z0Var.g).getValue()).booleanValue();
            InterfaceC0773a0 interfaceC0773a0 = z0Var.g;
            if (!zBooleanValue) {
                long jB = z ? z0Var.a().b() : j;
                z0Var.f(z0Var.a().f(jB));
                z0Var.k = z0Var.a().d(jB);
                if (z0Var.a().e(jB)) {
                    ((androidx.compose.runtime.L0) interfaceC0773a0).setValue(Boolean.TRUE);
                }
            }
            if (!((Boolean) ((androidx.compose.runtime.L0) interfaceC0773a0).getValue()).booleanValue()) {
                z2 = false;
            }
        }
        androidx.compose.runtime.snapshots.q qVar2 = this.j;
        int size2 = qVar2.size();
        for (int i2 = 0; i2 < size2; i2++) {
            E0 e0 = (E0) qVar2.get(i2);
            Object value = ((androidx.compose.runtime.L0) e0.d).getValue();
            J0 j03 = e0.a;
            if (!Intrinsics.b(value, j03.t())) {
                e0.i(j, z);
            }
            if (!Intrinsics.b(((androidx.compose.runtime.L0) e0.d).getValue(), j03.t())) {
                z2 = false;
            }
        }
        if (z2) {
            j();
        }
    }

    public final void j() {
        this.g.j(Long.MIN_VALUE);
        J0 j0 = this.a;
        if (j0 instanceof T) {
            j0.L(((androidx.compose.runtime.L0) this.d).getValue());
        }
        p(0L);
        ((androidx.compose.runtime.L0) ((InterfaceC0773a0) j0.b)).setValue(Boolean.FALSE);
        androidx.compose.runtime.snapshots.q qVar = this.j;
        int size = qVar.size();
        for (int i = 0; i < size; i++) {
            ((E0) qVar.get(i)).j();
        }
    }

    public final void k(float f) {
        androidx.compose.runtime.snapshots.q qVar = this.i;
        int size = qVar.size();
        for (int i = 0; i < size; i++) {
            z0 z0Var = (z0) qVar.get(i);
            z0Var.getClass();
            if (f == -4.0f || f == -5.0f) {
                C0270u0 c0270u0 = z0Var.f;
                if (c0270u0 != null) {
                    z0Var.a().h(c0270u0.c);
                    z0Var.e = null;
                    z0Var.f = null;
                }
                Object obj = f == -4.0f ? z0Var.a().d : z0Var.a().c;
                z0Var.a().h(obj);
                z0Var.a().i(obj);
                z0Var.f(obj);
                z0Var.l.j(z0Var.a().b());
            } else {
                z0Var.h.j(f);
            }
        }
        androidx.compose.runtime.snapshots.q qVar2 = this.j;
        int size2 = qVar2.size();
        for (int i2 = 0; i2 < size2; i2++) {
            ((E0) qVar2.get(i2)).k(f);
        }
    }

    public final void l() {
        androidx.compose.runtime.snapshots.q qVar = this.i;
        int size = qVar.size();
        for (int i = 0; i < size; i++) {
            ((z0) qVar.get(i)).h.j(-2.0f);
        }
        androidx.compose.runtime.snapshots.q qVar2 = this.j;
        int size2 = qVar2.size();
        for (int i2 = 0; i2 < size2; i2++) {
            ((E0) qVar2.get(i2)).l();
        }
    }

    public final void m(Object obj, Object obj2) {
        this.g.j(Long.MIN_VALUE);
        J0 j0 = this.a;
        ((androidx.compose.runtime.L0) ((InterfaceC0773a0) j0.b)).setValue(Boolean.FALSE);
        boolean zH = h();
        InterfaceC0773a0 interfaceC0773a0 = this.d;
        if (!zH || !Intrinsics.b(j0.t(), obj) || !Intrinsics.b(((androidx.compose.runtime.L0) interfaceC0773a0).getValue(), obj2)) {
            if (!Intrinsics.b(j0.t(), obj) && (j0 instanceof T)) {
                j0.L(obj);
            }
            ((androidx.compose.runtime.L0) interfaceC0773a0).setValue(obj2);
            ((androidx.compose.runtime.L0) this.k).setValue(Boolean.TRUE);
            ((androidx.compose.runtime.L0) this.e).setValue(new y0(obj, obj2));
        }
        androidx.compose.runtime.snapshots.q qVar = this.j;
        int size = qVar.size();
        for (int i = 0; i < size; i++) {
            E0 e0 = (E0) qVar.get(i);
            Intrinsics.e(e0, "null cannot be cast to non-null type androidx.compose.animation.core.Transition<kotlin.Any>");
            if (e0.h()) {
                e0.m(e0.a.t(), ((androidx.compose.runtime.L0) e0.d).getValue());
            }
        }
        androidx.compose.runtime.snapshots.q qVar2 = this.i;
        int size2 = qVar2.size();
        for (int i2 = 0; i2 < size2; i2++) {
            ((z0) qVar2.get(i2)).e(0L);
        }
    }

    public final void n(long j) {
        androidx.compose.runtime.J0 j0 = this.g;
        if (j0.i() == Long.MIN_VALUE) {
            j0.j(j);
        }
        p(j);
        ((androidx.compose.runtime.L0) this.h).setValue(Boolean.FALSE);
        androidx.compose.runtime.snapshots.q qVar = this.i;
        int size = qVar.size();
        for (int i = 0; i < size; i++) {
            ((z0) qVar.get(i)).e(j);
        }
        androidx.compose.runtime.snapshots.q qVar2 = this.j;
        int size2 = qVar2.size();
        for (int i2 = 0; i2 < size2; i2++) {
            E0 e0 = (E0) qVar2.get(i2);
            if (!Intrinsics.b(((androidx.compose.runtime.L0) e0.d).getValue(), e0.a.t())) {
                e0.n(j);
            }
        }
    }

    public final void o(X x) {
        androidx.compose.runtime.snapshots.q qVar = this.i;
        int size = qVar.size();
        for (int i = 0; i < size; i++) {
            z0 z0Var = (z0) qVar.get(i);
            if (!Intrinsics.b(z0Var.a().c, z0Var.a().d)) {
                z0Var.f = z0Var.a();
                z0Var.e = x;
            }
            androidx.compose.runtime.L0 l0 = (androidx.compose.runtime.L0) z0Var.j;
            ((androidx.compose.runtime.L0) z0Var.d).setValue(new C0270u0(z0Var.n, z0Var.a, l0.getValue(), l0.getValue(), z0Var.k.c()));
            z0Var.l.j(z0Var.a().b());
            z0Var.i = true;
        }
        androidx.compose.runtime.snapshots.q qVar2 = this.j;
        int size2 = qVar2.size();
        for (int i2 = 0; i2 < size2; i2++) {
            ((E0) qVar2.get(i2)).o(x);
        }
    }

    public final void p(long j) {
        if (this.b == null) {
            this.f.j(j);
        }
    }

    public final void q() {
        C0270u0 c0270u0;
        androidx.compose.runtime.snapshots.q qVar = this.i;
        int size = qVar.size();
        for (int i = 0; i < size; i++) {
            z0 z0Var = (z0) qVar.get(i);
            X x = z0Var.e;
            if (x != null && (c0270u0 = z0Var.f) != null) {
                long jC = kotlin.math.c.c(x.g * x.d);
                Object objF = c0270u0.f(jC);
                if (z0Var.i) {
                    z0Var.a().i(objF);
                }
                z0Var.a().h(objF);
                z0Var.l.j(z0Var.a().b());
                if (z0Var.b() == -2.0f || z0Var.i) {
                    z0Var.f(objF);
                } else {
                    z0Var.e(z0Var.o.e());
                }
                if (jC >= x.g) {
                    z0Var.e = null;
                    z0Var.f = null;
                } else {
                    x.c = false;
                }
            }
        }
        androidx.compose.runtime.snapshots.q qVar2 = this.j;
        int size2 = qVar2.size();
        for (int i2 = 0; i2 < size2; i2++) {
            ((E0) qVar2.get(i2)).q();
        }
    }

    public final void r(Object obj) {
        InterfaceC0773a0 interfaceC0773a0 = this.d;
        androidx.compose.runtime.L0 l0 = (androidx.compose.runtime.L0) interfaceC0773a0;
        if (Intrinsics.b(l0.getValue(), obj)) {
            return;
        }
        ((androidx.compose.runtime.L0) this.e).setValue(new y0(l0.getValue(), obj));
        J0 j0 = this.a;
        if (!Intrinsics.b(j0.t(), l0.getValue())) {
            j0.L(l0.getValue());
        }
        ((androidx.compose.runtime.L0) interfaceC0773a0).setValue(obj);
        if (this.g.i() == Long.MIN_VALUE) {
            ((androidx.compose.runtime.L0) this.h).setValue(Boolean.TRUE);
        }
        l();
    }

    public final String toString() {
        androidx.compose.runtime.snapshots.q qVar = this.i;
        int size = qVar.size();
        String str = "Transition animation values: ";
        for (int i = 0; i < size; i++) {
            str = str + ((z0) qVar.get(i)) + ", ";
        }
        return str;
    }
}
