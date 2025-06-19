package androidx.compose.animation.core;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.W0;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class z0 implements W0 {
    public final L0 a;
    public final InterfaceC0773a0 b;
    public final InterfaceC0773a0 c;
    public final InterfaceC0773a0 d;
    public X e;
    public C0270u0 f;
    public final InterfaceC0773a0 g;
    public final androidx.compose.runtime.F0 h;
    public boolean i;
    public final InterfaceC0773a0 j;
    public AbstractC0267t k;
    public final androidx.compose.runtime.J0 l;
    public boolean m;
    public final C0253l0 n;
    public final /* synthetic */ E0 o;

    /* JADX WARN: Type inference failed for: r9v12, types: [java.lang.Object, java.util.Map] */
    public z0(E0 e0, Object obj, AbstractC0267t abstractC0267t, L0 l0) {
        this.o = e0;
        this.a = l0;
        InterfaceC0773a0 interfaceC0773a0Z = C0776c.z(obj);
        this.b = interfaceC0773a0Z;
        Object objInvoke = null;
        InterfaceC0773a0 interfaceC0773a0Z2 = C0776c.z(AbstractC0240f.q(7, null));
        this.c = interfaceC0773a0Z2;
        this.d = C0776c.z(new C0270u0((D) ((androidx.compose.runtime.L0) interfaceC0773a0Z2).getValue(), l0, obj, ((androidx.compose.runtime.L0) interfaceC0773a0Z).getValue(), abstractC0267t));
        this.g = C0776c.z(Boolean.TRUE);
        this.h = C0776c.v(-1.0f);
        this.j = C0776c.z(obj);
        this.k = abstractC0267t;
        this.l = C0776c.x(a().b());
        Float f = (Float) V0.a.get(l0);
        if (f != null) {
            float fFloatValue = f.floatValue();
            AbstractC0267t abstractC0267t2 = (AbstractC0267t) l0.a.invoke(obj);
            int iB = abstractC0267t2.b();
            for (int i = 0; i < iB; i++) {
                abstractC0267t2.e(fFloatValue, i);
            }
            objInvoke = this.a.b.invoke(abstractC0267t2);
        }
        this.n = AbstractC0240f.q(3, objInvoke);
    }

    public final C0270u0 a() {
        return (C0270u0) ((androidx.compose.runtime.L0) this.d).getValue();
    }

    public final float b() {
        return this.h.i();
    }

    public final void e(long j) {
        if (b() == -1.0f) {
            this.m = true;
            if (Intrinsics.b(a().c, a().d)) {
                f(a().c);
            } else {
                f(a().f(j));
                this.k = a().d(j);
            }
        }
    }

    public final void f(Object obj) {
        ((androidx.compose.runtime.L0) this.j).setValue(obj);
    }

    public final void g(Object obj, boolean z) {
        C0270u0 c0270u0 = this.f;
        Object obj2 = c0270u0 != null ? c0270u0.c : null;
        androidx.compose.runtime.L0 l0 = (androidx.compose.runtime.L0) this.b;
        boolean zB = Intrinsics.b(obj2, l0.getValue());
        androidx.compose.runtime.J0 j0 = this.l;
        InterfaceC0773a0 interfaceC0773a0 = this.d;
        D d = this.n;
        if (zB) {
            ((androidx.compose.runtime.L0) interfaceC0773a0).setValue(new C0270u0(d, this.a, obj, obj, this.k.c()));
            this.i = true;
            j0.j(a().b());
            return;
        }
        InterfaceC0773a0 interfaceC0773a02 = this.c;
        if (!z || this.m || (((D) ((androidx.compose.runtime.L0) interfaceC0773a02).getValue()) instanceof C0253l0)) {
            d = (D) ((androidx.compose.runtime.L0) interfaceC0773a02).getValue();
        }
        E0 e0 = this.o;
        ((androidx.compose.runtime.L0) interfaceC0773a0).setValue(new C0270u0(e0.e() <= 0 ? d : new C0255m0(d, e0.e()), this.a, obj, l0.getValue(), this.k));
        j0.j(a().b());
        this.i = false;
        Boolean bool = Boolean.TRUE;
        InterfaceC0773a0 interfaceC0773a03 = e0.h;
        ((androidx.compose.runtime.L0) interfaceC0773a03).setValue(bool);
        if (e0.h()) {
            androidx.compose.runtime.snapshots.q qVar = e0.i;
            int size = qVar.size();
            long jMax = 0;
            for (int i = 0; i < size; i++) {
                z0 z0Var = (z0) qVar.get(i);
                jMax = Math.max(jMax, z0Var.l.i());
                z0Var.e(0L);
            }
            ((androidx.compose.runtime.L0) interfaceC0773a03).setValue(Boolean.FALSE);
        }
    }

    @Override // androidx.compose.runtime.W0
    public final Object getValue() {
        return ((androidx.compose.runtime.L0) this.j).getValue();
    }

    public final void h(Object obj, Object obj2, D d) {
        ((androidx.compose.runtime.L0) this.b).setValue(obj2);
        ((androidx.compose.runtime.L0) this.c).setValue(d);
        if (Intrinsics.b(a().d, obj) && Intrinsics.b(a().c, obj2)) {
            return;
        }
        g(obj, false);
    }

    public final void i(Object obj, D d) {
        if (this.i) {
            C0270u0 c0270u0 = this.f;
            if (Intrinsics.b(obj, c0270u0 != null ? c0270u0.c : null)) {
                return;
            }
        }
        InterfaceC0773a0 interfaceC0773a0 = this.b;
        if (Intrinsics.b(((androidx.compose.runtime.L0) interfaceC0773a0).getValue(), obj) && b() == -1.0f) {
            return;
        }
        ((androidx.compose.runtime.L0) interfaceC0773a0).setValue(obj);
        ((androidx.compose.runtime.L0) this.c).setValue(d);
        Object value = b() == -3.0f ? obj : ((androidx.compose.runtime.L0) this.j).getValue();
        InterfaceC0773a0 interfaceC0773a02 = this.g;
        g(value, !((Boolean) ((androidx.compose.runtime.L0) interfaceC0773a02).getValue()).booleanValue());
        ((androidx.compose.runtime.L0) interfaceC0773a02).setValue(Boolean.valueOf(b() == -3.0f));
        if (b() >= DefinitionKt.NO_Float_VALUE) {
            f(a().f((long) (b() * a().b())));
        } else if (b() == -3.0f) {
            f(obj);
        }
        this.i = false;
        this.h.j(-1.0f);
    }

    public final String toString() {
        return "current value: " + ((androidx.compose.runtime.L0) this.j).getValue() + ", target: " + ((androidx.compose.runtime.L0) this.b).getValue() + ", spec: " + ((D) ((androidx.compose.runtime.L0) this.c).getValue());
    }
}
