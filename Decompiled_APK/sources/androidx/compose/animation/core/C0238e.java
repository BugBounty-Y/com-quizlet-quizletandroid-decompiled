package androidx.compose.animation.core;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0238e {
    public final L0 a;
    public final Object b;
    public final C0258o c;
    public final InterfaceC0773a0 d;
    public final InterfaceC0773a0 e;
    public final W f;
    public final C0253l0 g;
    public final AbstractC0267t h;
    public final AbstractC0267t i;
    public final AbstractC0267t j;
    public final AbstractC0267t k;

    public C0238e(Object obj, L0 l0, Object obj2) {
        this.a = l0;
        this.b = obj2;
        C0258o c0258o = new C0258o(l0, obj, null, 60);
        this.c = c0258o;
        this.d = C0776c.z(Boolean.FALSE);
        this.e = C0776c.z(obj);
        this.f = new W();
        this.g = new C0253l0(obj2, 3);
        AbstractC0267t abstractC0267t = c0258o.c;
        boolean z = abstractC0267t instanceof C0260p;
        AbstractC0267t abstractC0267t2 = z ? AbstractC0240f.e : abstractC0267t instanceof C0262q ? AbstractC0240f.f : abstractC0267t instanceof r ? AbstractC0240f.g : AbstractC0240f.h;
        this.h = abstractC0267t2;
        AbstractC0267t abstractC0267t3 = z ? AbstractC0240f.a : abstractC0267t instanceof C0262q ? AbstractC0240f.b : abstractC0267t instanceof r ? AbstractC0240f.c : AbstractC0240f.d;
        this.i = abstractC0267t3;
        this.j = abstractC0267t2;
        this.k = abstractC0267t3;
    }

    public static final Object a(C0238e c0238e, Object obj) {
        AbstractC0267t abstractC0267t = c0238e.h;
        AbstractC0267t abstractC0267t2 = c0238e.j;
        boolean zB = Intrinsics.b(abstractC0267t2, abstractC0267t);
        AbstractC0267t abstractC0267t3 = c0238e.k;
        if (!zB || !Intrinsics.b(abstractC0267t3, c0238e.i)) {
            L0 l0 = c0238e.a;
            AbstractC0267t abstractC0267t4 = (AbstractC0267t) l0.a.invoke(obj);
            int iB = abstractC0267t4.b();
            boolean z = false;
            for (int i = 0; i < iB; i++) {
                if (abstractC0267t4.a(i) < abstractC0267t2.a(i) || abstractC0267t4.a(i) > abstractC0267t3.a(i)) {
                    abstractC0267t4.e(kotlin.ranges.l.b(abstractC0267t4.a(i), abstractC0267t2.a(i), abstractC0267t3.a(i)), i);
                    z = true;
                }
            }
            if (z) {
                return l0.b.invoke(abstractC0267t4);
            }
        }
        return obj;
    }

    public static final void b(C0238e c0238e) {
        C0258o c0258o = c0238e.c;
        c0258o.c.d();
        c0258o.d = Long.MIN_VALUE;
        ((androidx.compose.runtime.L0) c0238e.d).setValue(Boolean.FALSE);
    }

    public static Object c(C0238e c0238e, Object obj, InterfaceC0256n interfaceC0256n, Function1 function1, kotlin.coroutines.h hVar, int i) {
        if ((i & 2) != 0) {
            interfaceC0256n = c0238e.g;
        }
        InterfaceC0256n interfaceC0256n2 = interfaceC0256n;
        Object objInvoke = c0238e.a.b.invoke(c0238e.c.c);
        if ((i & 8) != 0) {
            function1 = null;
        }
        Object objD = c0238e.d();
        L0 l0 = c0238e.a;
        return W.a(c0238e.f, new C0232b(c0238e, objInvoke, new C0270u0(interfaceC0256n2, l0, objD, obj, (AbstractC0267t) l0.a.invoke(objInvoke)), c0238e.c.d, function1, null), hVar);
    }

    public final Object d() {
        return ((androidx.compose.runtime.L0) this.c.b).getValue();
    }

    public final boolean e() {
        return ((Boolean) ((androidx.compose.runtime.L0) this.d).getValue()).booleanValue();
    }

    public final Object f(Object obj, kotlin.coroutines.h hVar) {
        Object objA = W.a(this.f, new C0234c(this, obj, null), hVar);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : Unit.a;
    }

    public final Object g(kotlin.coroutines.jvm.internal.i iVar) {
        Object objA = W.a(this.f, new C0236d(this, null), iVar);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : Unit.a;
    }

    public /* synthetic */ C0238e(Object obj, L0 l0, Object obj2, int i) {
        this(obj, l0, (i & 4) != 0 ? null : obj2);
    }
}
