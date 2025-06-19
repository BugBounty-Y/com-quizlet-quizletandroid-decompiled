package androidx.compose.animation.core;

import androidx.compose.animation.C0278e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public abstract class I0 {
    public static final Object a = kotlin.l.a(kotlin.m.c, F0.a);

    /* JADX WARN: Type inference failed for: r2v4, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r4v4, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r5v7, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public static final w0 a(E0 e0, L0 l0, String str, InterfaceC0806l interfaceC0806l, int i, int i2) {
        C0272v0 c0272v0;
        if ((i2 & 2) != 0) {
            str = "DeferredAnimation";
        }
        boolean zF = ((C0814p) interfaceC0806l).f(e0);
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        androidx.compose.runtime.V v = C0804k.a;
        if (zF || objI == v) {
            objI = new w0(e0, l0, str);
            c0814p.i0(objI);
        }
        w0 w0Var = (w0) objI;
        boolean zF2 = c0814p.f(e0) | c0814p.h(w0Var);
        Object objI2 = c0814p.I();
        if (zF2 || objI2 == v) {
            objI2 = new C0278e(5, e0, w0Var);
            c0814p.i0(objI2);
        }
        C0776c.d(w0Var, (Function1) objI2, c0814p);
        if (e0.h() && (c0272v0 = (C0272v0) ((androidx.compose.runtime.L0) w0Var.b).getValue()) != null) {
            ?? r2 = c0272v0.c;
            E0 e02 = w0Var.c;
            c0272v0.a.h(r2.invoke(e02.f().a()), c0272v0.c.invoke(e02.f().c()), (D) c0272v0.b.invoke(e02.f()));
        }
        return w0Var;
    }

    public static final z0 b(E0 e0, Object obj, Object obj2, D d, L0 l0, InterfaceC0806l interfaceC0806l, int i) {
        boolean zF = ((C0814p) interfaceC0806l).f(e0);
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        androidx.compose.runtime.V v = C0804k.a;
        if (zF || objI == v) {
            AbstractC0267t abstractC0267t = (AbstractC0267t) l0.a.invoke(obj2);
            abstractC0267t.d();
            objI = new z0(e0, obj, abstractC0267t, l0);
            c0814p.i0(objI);
        }
        z0 z0Var = (z0) objI;
        if (e0.h()) {
            z0Var.h(obj, obj2, d);
        } else {
            z0Var.i(obj2, d);
        }
        boolean zF2 = c0814p.f(e0) | c0814p.f(z0Var);
        Object objI2 = c0814p.I();
        if (zF2 || objI2 == v) {
            objI2 = new C0278e(6, e0, z0Var);
            c0814p.i0(objI2);
        }
        C0776c.d(z0Var, (Function1) objI2, c0814p);
        return z0Var;
    }

    public static final E0 c(J0 j0, String str, InterfaceC0806l interfaceC0806l, int i) {
        int i2 = (i & 14) ^ 6;
        boolean z = true;
        boolean z2 = (i2 > 4 && ((C0814p) interfaceC0806l).f(j0)) || (i & 6) == 4;
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        Object obj = C0804k.a;
        if (z2 || objI == obj) {
            objI = new E0(j0, null, str);
            c0814p.i0(objI);
        }
        E0 e0 = (E0) objI;
        if (j0 instanceof C0247i0) {
            c0814p.X(1030413636);
            C0247i0 c0247i0 = (C0247i0) j0;
            Object value = ((androidx.compose.runtime.L0) c0247i0.d).getValue();
            Object value2 = ((androidx.compose.runtime.L0) c0247i0.c).getValue();
            if ((i2 <= 4 || !c0814p.f(j0)) && (i & 6) != 4) {
                z = false;
            }
            Object objI2 = c0814p.I();
            if (z || objI2 == obj) {
                objI2 = new G0(j0, null);
                c0814p.i0(objI2);
            }
            C0776c.g(value, value2, (Function2) objI2, c0814p);
            c0814p.p(false);
        } else {
            c0814p.X(1030875195);
            e0.a(j0.I(), c0814p, 0);
            c0814p.p(false);
        }
        boolean zF = c0814p.f(e0);
        Object objI3 = c0814p.I();
        if (zF || objI3 == obj) {
            objI3 = new androidx.compose.animation.L(e0, 1);
            c0814p.i0(objI3);
        }
        C0776c.d(e0, (Function1) objI3, c0814p);
        return e0;
    }

    public static final E0 d(Object obj, String str, InterfaceC0806l interfaceC0806l, int i, int i2) {
        if ((i2 & 2) != 0) {
            str = null;
        }
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        androidx.compose.runtime.V v = C0804k.a;
        if (objI == v) {
            objI = new E0(new T(obj), null, str);
            c0814p.i0(objI);
        }
        E0 e0 = (E0) objI;
        e0.a(obj, c0814p, (i & 8) | 48 | (i & 14));
        Object objI2 = c0814p.I();
        if (objI2 == v) {
            objI2 = new androidx.compose.animation.L(e0, 2);
            c0814p.i0(objI2);
        }
        C0776c.d(e0, (Function1) objI2, c0814p);
        return e0;
    }
}
