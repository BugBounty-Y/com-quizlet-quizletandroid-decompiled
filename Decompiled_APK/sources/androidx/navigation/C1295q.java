package androidx.navigation;

import android.os.Bundle;
import android.util.Log;
import androidx.lifecycle.C1247h;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.C4927s;
import kotlin.collections.CollectionsKt;
import kotlin.collections.b0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* renamed from: androidx.navigation.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1295q {
    public final com.quizlet.shared.usecase.folderstudymaterials.a a;
    public final s0 b;
    public final s0 c;
    public boolean d;
    public final Z e;
    public final Z f;
    public final W g;
    public final /* synthetic */ r h;

    public C1295q(r rVar, W navigator) {
        Intrinsics.checkNotNullParameter(navigator, "navigator");
        this.h = rVar;
        this.a = new com.quizlet.shared.usecase.folderstudymaterials.a(4);
        s0 s0VarC = e0.c(kotlin.collections.K.a);
        this.b = s0VarC;
        s0 s0VarC2 = e0.c(kotlin.collections.M.a);
        this.c = s0VarC2;
        this.e = new Z(s0VarC);
        this.f = new Z(s0VarC2);
        this.g = navigator;
    }

    public final void a(C1291m backStackEntry) {
        Intrinsics.checkNotNullParameter(backStackEntry, "backStackEntry");
        Intrinsics.checkNotNullParameter(backStackEntry, "backStackEntry");
        synchronized (this.a) {
            s0 s0Var = this.b;
            ArrayList arrayListD0 = CollectionsKt.d0((Collection) s0Var.getValue(), backStackEntry);
            s0Var.getClass();
            s0Var.m(null, arrayListD0);
            Unit unit = Unit.a;
        }
    }

    public final C1291m b(B destination, Bundle bundle) {
        Intrinsics.checkNotNullParameter(destination, "destination");
        androidx.navigation.internal.j jVar = this.h.b;
        jVar.getClass();
        Intrinsics.checkNotNullParameter(destination, "destination");
        r rVar = jVar.a;
        return T.a(rVar.c, destination, bundle, jVar.i(), jVar.o);
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0088  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(androidx.navigation.C1291m r8) {
        /*
            r7 = this;
            java.lang.String r0 = "entry"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            androidx.navigation.r r1 = r7.h
            androidx.navigation.internal.j r1 = r1.b
            androidx.navigation.p r2 = new androidx.navigation.p
            r2.<init>(r7, r8)
            r1.getClass()
            java.lang.String r3 = "state"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r3)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            java.lang.String r0 = "superCallback"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r0)
            java.util.LinkedHashMap r0 = r1.w
            java.lang.Object r3 = r0.get(r8)
            java.lang.Boolean r4 = java.lang.Boolean.TRUE
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r3, r4)
            r2.invoke()
            r0.remove(r8)
            kotlin.collections.s r0 = r1.f
            boolean r2 = r0.contains(r8)
            r4 = 0
            kotlinx.coroutines.flow.s0 r5 = r1.h
            if (r2 != 0) goto L99
            r1.t(r8)
            androidx.navigation.internal.c r2 = r8.h
            androidx.lifecycle.L r2 = r2.j
            androidx.lifecycle.B r2 = r2.d
            androidx.lifecycle.B r6 = androidx.lifecycle.B.c
            boolean r2 = r2.a(r6)
            if (r2 == 0) goto L51
            androidx.lifecycle.B r2 = androidx.lifecycle.B.a
            r8.a(r2)
        L51:
            boolean r2 = r0.isEmpty()
            java.lang.String r8 = r8.f
            if (r2 == 0) goto L5a
            goto L73
        L5a:
            java.util.Iterator r0 = r0.iterator()
        L5e:
            boolean r2 = r0.hasNext()
            if (r2 == 0) goto L73
            java.lang.Object r2 = r0.next()
            androidx.navigation.m r2 = (androidx.navigation.C1291m) r2
            java.lang.String r2 = r2.f
            boolean r2 = kotlin.jvm.internal.Intrinsics.b(r2, r8)
            if (r2 == 0) goto L5e
            goto L8b
        L73:
            if (r3 != 0) goto L8b
            androidx.navigation.s r0 = r1.o
            if (r0 == 0) goto L8b
            java.lang.String r2 = "backStackEntryId"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r2)
            java.util.LinkedHashMap r0 = r0.b
            java.lang.Object r8 = r0.remove(r8)
            androidx.lifecycle.B0 r8 = (androidx.lifecycle.B0) r8
            if (r8 == 0) goto L8b
            r8.a()
        L8b:
            r1.u()
            java.util.ArrayList r8 = r1.r()
            r5.getClass()
            r5.m(r4, r8)
            return
        L99:
            boolean r8 = r7.d
            if (r8 != 0) goto Lb6
            r1.u()
            java.util.ArrayList r8 = kotlin.collections.CollectionsKt.y0(r0)
            kotlinx.coroutines.flow.s0 r0 = r1.g
            r0.getClass()
            r0.m(r4, r8)
            java.util.ArrayList r8 = r1.r()
            r5.getClass()
            r5.m(r4, r8)
        Lb6:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.C1295q.c(androidx.navigation.m):void");
    }

    public final void d(C1291m popUpTo, boolean z) {
        Intrinsics.checkNotNullParameter(popUpTo, "popUpTo");
        androidx.navigation.internal.j jVar = this.h.b;
        C1294p superCallback = new C1294p(this, popUpTo, z);
        jVar.getClass();
        Intrinsics.checkNotNullParameter(this, "state");
        Intrinsics.checkNotNullParameter(popUpTo, "popUpTo");
        Intrinsics.checkNotNullParameter(superCallback, "superCallback");
        W wC = jVar.s.c(popUpTo.b.a);
        jVar.w.put(popUpTo, Boolean.valueOf(z));
        if (!wC.equals(this.g)) {
            Object obj = jVar.t.get(wC);
            Intrinsics.d(obj);
            ((C1295q) obj).d(popUpTo, z);
            return;
        }
        androidx.navigation.internal.f fVar = jVar.v;
        if (fVar != null) {
            fVar.invoke(popUpTo);
            superCallback.invoke();
            return;
        }
        C1247h onComplete = new C1247h(superCallback, 3);
        Intrinsics.checkNotNullParameter(popUpTo, "popUpTo");
        Intrinsics.checkNotNullParameter(onComplete, "onComplete");
        C4927s c4927s = jVar.f;
        int iIndexOf = c4927s.indexOf(popUpTo);
        if (iIndexOf < 0) {
            String message = "Ignoring pop of " + popUpTo + " as it was not found on the current back stack";
            Intrinsics.checkNotNullParameter("NavController", "tag");
            Intrinsics.checkNotNullParameter(message, "message");
            Log.i("NavController", message);
            return;
        }
        int i = iIndexOf + 1;
        if (i != c4927s.c) {
            jVar.n(((C1291m) c4927s.get(i)).b.b.c, true, false);
        }
        androidx.navigation.internal.j.q(jVar, popUpTo);
        onComplete.invoke();
        jVar.b.invoke();
        jVar.b();
    }

    public final void e(C1291m popUpTo, boolean z) {
        Object objPrevious;
        Intrinsics.checkNotNullParameter(popUpTo, "popUpTo");
        Intrinsics.checkNotNullParameter(popUpTo, "popUpTo");
        s0 s0Var = this.c;
        Iterable iterable = (Iterable) s0Var.getValue();
        boolean z2 = iterable instanceof Collection;
        Z z3 = this.e;
        if (!z2 || !((Collection) iterable).isEmpty()) {
            Iterator it2 = iterable.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                if (((C1291m) it2.next()) == popUpTo) {
                    Iterable iterable2 = (Iterable) ((s0) z3.a).getValue();
                    if ((iterable2 instanceof Collection) && ((Collection) iterable2).isEmpty()) {
                        return;
                    }
                    Iterator it3 = iterable2.iterator();
                    while (it3.hasNext()) {
                        if (((C1291m) it3.next()) == popUpTo) {
                        }
                    }
                    return;
                }
            }
        }
        s0Var.m(null, b0.g((Set) s0Var.getValue(), popUpTo));
        List list = (List) ((s0) z3.a).getValue();
        ListIterator listIterator = list.listIterator(list.size());
        while (true) {
            if (!listIterator.hasPrevious()) {
                objPrevious = null;
                break;
            }
            objPrevious = listIterator.previous();
            C1291m c1291m = (C1291m) objPrevious;
            if (!Intrinsics.b(c1291m, popUpTo)) {
                kotlinx.coroutines.flow.X x = z3.a;
                if (((List) ((s0) x).getValue()).lastIndexOf(c1291m) < ((List) ((s0) x).getValue()).lastIndexOf(popUpTo)) {
                    break;
                }
            }
        }
        C1291m c1291m2 = (C1291m) objPrevious;
        if (c1291m2 != null) {
            s0Var.m(null, b0.g((Set) s0Var.getValue(), c1291m2));
        }
        d(popUpTo, z);
    }

    public final void f(C1291m backStackEntry) {
        Intrinsics.checkNotNullParameter(backStackEntry, "backStackEntry");
        androidx.navigation.internal.j jVar = this.h.b;
        jVar.getClass();
        Intrinsics.checkNotNullParameter(this, "state");
        Intrinsics.checkNotNullParameter(backStackEntry, "backStackEntry");
        W wC = jVar.s.c(backStackEntry.b.a);
        if (!wC.equals(this.g)) {
            Object obj = jVar.t.get(wC);
            if (obj == null) {
                throw new IllegalStateException(android.support.v4.media.session.a.t(new StringBuilder("NavigatorBackStack for "), backStackEntry.b.a, " should already be created").toString());
            }
            ((C1295q) obj).f(backStackEntry);
            return;
        }
        Function1 function1 = jVar.u;
        if (function1 != null) {
            function1.invoke(backStackEntry);
            a(backStackEntry);
            return;
        }
        String message = "Ignoring add of destination " + backStackEntry.b + " outside of the call to navigate(). ";
        Intrinsics.checkNotNullParameter("NavController", "tag");
        Intrinsics.checkNotNullParameter(message, "message");
        Log.i("NavController", message);
    }

    public final void g(C1291m backStackEntry) {
        Intrinsics.checkNotNullParameter(backStackEntry, "backStackEntry");
        s0 s0Var = this.c;
        Iterable iterable = (Iterable) s0Var.getValue();
        boolean z = iterable instanceof Collection;
        Z z2 = this.e;
        if (!z || !((Collection) iterable).isEmpty()) {
            Iterator it2 = iterable.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                if (((C1291m) it2.next()) == backStackEntry) {
                    Iterable iterable2 = (Iterable) ((s0) z2.a).getValue();
                    if (!(iterable2 instanceof Collection) || !((Collection) iterable2).isEmpty()) {
                        Iterator it3 = iterable2.iterator();
                        while (it3.hasNext()) {
                            if (((C1291m) it3.next()) == backStackEntry) {
                                return;
                            }
                        }
                    }
                }
            }
        }
        C1291m c1291m = (C1291m) CollectionsKt.V((List) ((s0) z2.a).getValue());
        if (c1291m != null) {
            LinkedHashSet linkedHashSetG = b0.g((Set) s0Var.getValue(), c1291m);
            s0Var.getClass();
            s0Var.m(null, linkedHashSetG);
        }
        LinkedHashSet linkedHashSetG2 = b0.g((Set) s0Var.getValue(), backStackEntry);
        s0Var.getClass();
        s0Var.m(null, linkedHashSetG2);
        f(backStackEntry);
    }
}
