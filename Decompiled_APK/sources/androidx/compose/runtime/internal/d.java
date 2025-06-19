package androidx.compose.runtime.internal;

import androidx.compose.animation.core.D0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.InterfaceC0815p0;
import java.io.Serializable;
import java.util.ArrayList;
import kotlin.InterfaceC4938g;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes.dex */
public final class d implements b {
    public final int a;
    public final boolean b;
    public Object c;
    public C0813o0 d;
    public ArrayList e;

    public d(boolean z, int i, Object obj) {
        this.a = i;
        this.b = z;
        this.c = obj;
    }

    public final Object a(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(this.a);
        f(c0814p);
        int iA = i | (c0814p.f(this) ? e.a(2, 0) : e.a(1, 0));
        Object obj = this.c;
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Function2<@[ParameterName(name = \"c\")] androidx.compose.runtime.Composer, @[ParameterName(name = \"changed\")] kotlin.Int, kotlin.Any?>");
        O.d(2, obj);
        Object objInvoke = ((Function2) obj).invoke(c0814p, Integer.valueOf(iA));
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new c(2, this, d.class, "invoke", "invoke(Landroidx/compose/runtime/Composer;I)Ljava/lang/Object;", 8, 0);
        }
        return objInvoke;
    }

    public final Object b(Object obj, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(this.a);
        f(c0814p);
        int iA = c0814p.f(this) ? e.a(2, 1) : e.a(1, 1);
        Object obj2 = this.c;
        Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Function3<@[ParameterName(name = \"p1\")] kotlin.Any?, @[ParameterName(name = \"c\")] androidx.compose.runtime.Composer, @[ParameterName(name = \"changed\")] kotlin.Int, kotlin.Any?>");
        O.d(3, obj2);
        Object objInvoke = ((kotlin.jvm.functions.c) obj2).invoke(obj, c0814p, Integer.valueOf(iA | i));
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new D0(this, obj, i, 12);
        }
        return objInvoke;
    }

    @Override // kotlin.jvm.functions.e
    public final /* bridge */ /* synthetic */ Object c(Object obj, Object obj2, Object obj3, Object obj4, Serializable serializable) {
        return e(obj, obj2, obj3, (InterfaceC0806l) obj4, ((Number) serializable).intValue());
    }

    public final Object d(Object obj, Object obj2, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(this.a);
        f(c0814p);
        int iA = c0814p.f(this) ? e.a(2, 2) : e.a(1, 2);
        Object obj3 = this.c;
        Intrinsics.e(obj3, "null cannot be cast to non-null type kotlin.Function4<@[ParameterName(name = \"p1\")] kotlin.Any?, @[ParameterName(name = \"p2\")] kotlin.Any?, @[ParameterName(name = \"c\")] androidx.compose.runtime.Composer, @[ParameterName(name = \"changed\")] kotlin.Int, kotlin.Any?>");
        O.d(4, obj3);
        Object objInvoke = ((kotlin.jvm.functions.d) obj3).invoke(obj, obj2, c0814p, Integer.valueOf(iA | i));
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.a(i, 6, this, obj, obj2);
        }
        return objInvoke;
    }

    public final Object e(Object obj, Object obj2, Object obj3, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(this.a);
        f(c0814p);
        int iA = c0814p.f(this) ? e.a(2, 3) : e.a(1, 3);
        Object obj4 = this.c;
        Intrinsics.e(obj4, "null cannot be cast to non-null type kotlin.Function5<@[ParameterName(name = \"p1\")] kotlin.Any?, @[ParameterName(name = \"p2\")] kotlin.Any?, @[ParameterName(name = \"p3\")] kotlin.Any?, @[ParameterName(name = \"c\")] androidx.compose.runtime.Composer, @[ParameterName(name = \"changed\")] kotlin.Int, kotlin.Any?>");
        O.d(5, obj4);
        Object objC = ((kotlin.jvm.functions.e) obj4).c(obj, obj2, obj3, c0814p, Integer.valueOf(iA | i));
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.b(this, obj, obj2, obj3, i, 5);
        }
        return objC;
    }

    public final void f(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p;
        C0813o0 c0813o0V;
        if (!this.b || (c0813o0V = (c0814p = (C0814p) interfaceC0806l).v()) == null) {
            return;
        }
        c0814p.getClass();
        c0813o0V.a |= 1;
        if (e.f(this.d, c0813o0V)) {
            this.d = c0813o0V;
            return;
        }
        ArrayList arrayList = this.e;
        if (arrayList == null) {
            ArrayList arrayList2 = new ArrayList();
            this.e = arrayList2;
            arrayList2.add(c0813o0V);
            return;
        }
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            if (e.f((C0813o0) arrayList.get(i), c0813o0V)) {
                arrayList.set(i, c0813o0V);
                return;
            }
        }
        arrayList.add(c0813o0V);
    }

    public final void g(InterfaceC4938g interfaceC4938g) {
        if (Intrinsics.b(this.c, interfaceC4938g)) {
            return;
        }
        boolean z = this.c == null;
        this.c = interfaceC4938g;
        if (z || !this.b) {
            return;
        }
        C0813o0 c0813o0 = this.d;
        if (c0813o0 != null) {
            InterfaceC0815p0 interfaceC0815p0 = c0813o0.b;
            if (interfaceC0815p0 != null) {
                interfaceC0815p0.b(c0813o0, null);
            }
            this.d = null;
        }
        ArrayList arrayList = this.e;
        if (arrayList != null) {
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                C0813o0 c0813o02 = (C0813o0) arrayList.get(i);
                InterfaceC0815p0 interfaceC0815p02 = c0813o02.b;
                if (interfaceC0815p02 != null) {
                    interfaceC0815p02.b(c0813o02, null);
                }
            }
            arrayList.clear();
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final /* bridge */ /* synthetic */ Object invoke(Object obj, Object obj2) {
        return a((InterfaceC0806l) obj, ((Number) obj2).intValue());
    }

    @Override // kotlin.jvm.functions.c
    public final /* bridge */ /* synthetic */ Object invoke(Object obj, Object obj2, Object obj3) {
        return b(obj, (InterfaceC0806l) obj2, ((Number) obj3).intValue());
    }

    @Override // kotlin.jvm.functions.d
    public final /* bridge */ /* synthetic */ Object invoke(Object obj, Object obj2, Object obj3, Object obj4) {
        return d(obj, obj2, (InterfaceC0806l) obj3, ((Number) obj4).intValue());
    }
}
