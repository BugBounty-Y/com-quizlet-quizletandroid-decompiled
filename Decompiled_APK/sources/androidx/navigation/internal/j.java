package androidx.navigation.internal;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import androidx.compose.ui.platform.X0;
import androidx.lifecycle.B;
import androidx.lifecycle.B0;
import androidx.lifecycle.J;
import androidx.navigation.A;
import androidx.navigation.C1265a;
import androidx.navigation.C1291m;
import androidx.navigation.C1292n;
import androidx.navigation.C1293o;
import androidx.navigation.C1295q;
import androidx.navigation.C1296s;
import androidx.navigation.D;
import androidx.navigation.InterfaceC1286h;
import androidx.navigation.W;
import androidx.navigation.X;
import androidx.navigation.r;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import com.google.android.gms.internal.mlkit_vision_camera.H1;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import kotlin.Pair;
import kotlin.collections.C4927s;
import kotlin.collections.CollectionsKt;
import kotlin.collections.G;
import kotlin.collections.K;
import kotlin.collections.V;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.H;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import kotlin.sequences.Sequence;
import kotlin.sequences.t;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes.dex */
public final class j {
    public final r a;
    public final C1293o b;
    public D c;
    public Bundle d;
    public Bundle[] e;
    public final C4927s f;
    public final s0 g;
    public final s0 h;
    public final Z i;
    public final LinkedHashMap j;
    public final LinkedHashMap k;
    public final LinkedHashMap l;
    public final LinkedHashMap m;
    public J n;
    public C1296s o;
    public final ArrayList p;
    public B q;
    public final X0 r;
    public final X s;
    public final LinkedHashMap t;
    public Function1 u;
    public f v;
    public final LinkedHashMap w;
    public int x;
    public final ArrayList y;
    public final d0 z;

    public j(r navController, C1293o updateOnBackPressedCallbackEnabledCallback) {
        Intrinsics.checkNotNullParameter(navController, "navController");
        Intrinsics.checkNotNullParameter(updateOnBackPressedCallbackEnabledCallback, "updateOnBackPressedCallbackEnabledCallback");
        this.a = navController;
        this.b = updateOnBackPressedCallbackEnabledCallback;
        this.f = new C4927s();
        K k = K.a;
        this.g = e0.c(k);
        s0 s0VarC = e0.c(k);
        this.h = s0VarC;
        this.i = new Z(s0VarC);
        this.j = new LinkedHashMap();
        this.k = new LinkedHashMap();
        this.l = new LinkedHashMap();
        this.m = new LinkedHashMap();
        this.p = new ArrayList();
        this.q = B.b;
        this.r = new X0(this, 1);
        this.s = new X();
        this.t = new LinkedHashMap();
        this.w = new LinkedHashMap();
        this.y = new ArrayList();
        this.z = e0.b(1, 0, kotlinx.coroutines.channels.a.b, 2);
    }

    public static androidx.navigation.B e(int i, androidx.navigation.B destination, androidx.navigation.B b, boolean z) {
        Intrinsics.checkNotNullParameter(destination, "destination");
        if (destination.b.c == i && (b == null || (destination.equals(b) && Intrinsics.b(destination.c, b.c)))) {
            return destination;
        }
        D d = destination instanceof D ? (D) destination : null;
        if (d == null) {
            d = destination.c;
            Intrinsics.d(d);
        }
        return d.f.u(i, d, b, z);
    }

    public static /* synthetic */ void q(j jVar, C1291m c1291m) {
        jVar.p(c1291m, false, new C4927s());
    }

    /* JADX WARN: Removed duplicated region for block: B:45:0x00c0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(androidx.navigation.B r12, android.os.Bundle r13, androidx.navigation.C1291m r14, java.util.List r15) {
        /*
            Method dump skipped, instructions count: 524
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.internal.j.a(androidx.navigation.B, android.os.Bundle, androidx.navigation.m, java.util.List):void");
    }

    public final boolean b() {
        C4927s c4927s;
        while (true) {
            c4927s = this.f;
            if (c4927s.isEmpty() || !(((C1291m) c4927s.last()).b instanceof D)) {
                break;
            }
            q(this, (C1291m) c4927s.last());
        }
        C1291m c1291m = (C1291m) c4927s.k();
        ArrayList arrayList = this.y;
        if (c1291m != null) {
            arrayList.add(c1291m);
        }
        this.x++;
        u();
        int i = this.x - 1;
        this.x = i;
        if (i == 0) {
            ArrayList arrayListY0 = CollectionsKt.y0(arrayList);
            arrayList.clear();
            Iterator it2 = arrayListY0.iterator();
            while (it2.hasNext()) {
                C1291m c1291m2 = (C1291m) it2.next();
                Iterator it3 = this.p.iterator();
                if (it3.hasNext()) {
                    if (it3.next() != null) {
                        throw new ClassCastException();
                    }
                    androidx.navigation.B b = c1291m2.b;
                    c1291m2.h.a();
                    throw null;
                }
                this.z.h(c1291m2);
            }
            ArrayList arrayListY02 = CollectionsKt.y0(c4927s);
            s0 s0Var = this.g;
            s0Var.getClass();
            s0Var.m(null, arrayListY02);
            ArrayList arrayListR = r();
            s0 s0Var2 = this.h;
            s0Var2.getClass();
            s0Var2.m(null, arrayListR);
        }
        return c1291m != null;
    }

    public final boolean c(ArrayList popOperations, androidx.navigation.B foundDestination, boolean z, boolean z2) {
        j jVar;
        boolean z3;
        com.google.android.gms.cloudmessaging.k kVar;
        Intrinsics.checkNotNullParameter(popOperations, "popOperations");
        Intrinsics.checkNotNullParameter(foundDestination, "foundDestination");
        F f = new F();
        C4927s c4927s = new C4927s();
        Iterator it2 = popOperations.iterator();
        while (true) {
            if (!it2.hasNext()) {
                jVar = this;
                z3 = z2;
                break;
            }
            W navigator = (W) it2.next();
            F f2 = new F();
            C1291m popUpTo = (C1291m) this.f.last();
            jVar = this;
            z3 = z2;
            f handler = new f(0, f2, f, jVar, c4927s, z3);
            Intrinsics.checkNotNullParameter(navigator, "navigator");
            Intrinsics.checkNotNullParameter(popUpTo, "popUpTo");
            Intrinsics.checkNotNullParameter(handler, "handler");
            jVar.v = handler;
            navigator.f(popUpTo, z3);
            jVar.v = null;
            if (!f2.a) {
                break;
            }
            z2 = z3;
        }
        if (z3) {
            LinkedHashMap linkedHashMap = jVar.l;
            if (!z) {
                Sequence sequenceC = kotlin.sequences.n.c(new C1265a(21), foundDestination);
                final int i = 0;
                Function1 predicate = new Function1(this) { // from class: androidx.navigation.internal.g
                    public final /* synthetic */ j b;

                    {
                        this.b = this;
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        androidx.navigation.B destination = (androidx.navigation.B) obj;
                        switch (i) {
                            case 0:
                                Intrinsics.checkNotNullParameter(destination, "destination");
                                break;
                            default:
                                Intrinsics.checkNotNullParameter(destination, "destination");
                                break;
                        }
                        return Boolean.valueOf(!this.b.l.containsKey(Integer.valueOf(destination.b.c)));
                    }
                };
                Intrinsics.checkNotNullParameter(sequenceC, "<this>");
                Intrinsics.checkNotNullParameter(predicate, "predicate");
                kotlin.sequences.e eVar = new kotlin.sequences.e(new t(sequenceC, predicate, 0));
                while (eVar.hasNext()) {
                    Integer numValueOf = Integer.valueOf(((androidx.navigation.B) eVar.next()).b.c);
                    C1292n c1292n = (C1292n) c4927s.h();
                    linkedHashMap.put(numValueOf, c1292n != null ? (String) c1292n.a.c : null);
                }
            }
            if (!c4927s.isEmpty()) {
                C1292n c1292n2 = (C1292n) c4927s.first();
                Sequence sequenceC2 = kotlin.sequences.n.c(new C1265a(22), d(c1292n2.a.b, null));
                final int i2 = 1;
                Function1 predicate2 = new Function1(this) { // from class: androidx.navigation.internal.g
                    public final /* synthetic */ j b;

                    {
                        this.b = this;
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        androidx.navigation.B destination = (androidx.navigation.B) obj;
                        switch (i2) {
                            case 0:
                                Intrinsics.checkNotNullParameter(destination, "destination");
                                break;
                            default:
                                Intrinsics.checkNotNullParameter(destination, "destination");
                                break;
                        }
                        return Boolean.valueOf(!this.b.l.containsKey(Integer.valueOf(destination.b.c)));
                    }
                };
                Intrinsics.checkNotNullParameter(sequenceC2, "<this>");
                Intrinsics.checkNotNullParameter(predicate2, "predicate");
                kotlin.sequences.e eVar2 = new kotlin.sequences.e(new t(sequenceC2, predicate2, 0));
                while (true) {
                    boolean zHasNext = eVar2.hasNext();
                    kVar = c1292n2.a;
                    if (!zHasNext) {
                        break;
                    }
                    linkedHashMap.put(Integer.valueOf(((androidx.navigation.B) eVar2.next()).b.c), (String) kVar.c);
                }
                if (linkedHashMap.values().contains((String) kVar.c)) {
                    jVar.m.put((String) kVar.c, c4927s);
                }
            }
        }
        jVar.b.invoke();
        return f.a;
    }

    public final androidx.navigation.B d(int i, androidx.navigation.B b) {
        androidx.navigation.B b2;
        D d = this.c;
        if (d == null) {
            return null;
        }
        if (d.b.c == i) {
            if (b == null) {
                return d;
            }
            if (Intrinsics.b(d, b) && b.c == null) {
                return this.c;
            }
        }
        C1291m c1291m = (C1291m) this.f.k();
        if (c1291m == null || (b2 = c1291m.b) == null) {
            b2 = this.c;
            Intrinsics.d(b2);
        }
        return e(i, b2, b, false);
    }

    public final C1291m f(int i) {
        Object objPrevious;
        C4927s c4927s = this.f;
        ListIterator<E> listIterator = c4927s.listIterator(c4927s.size());
        while (true) {
            if (!listIterator.hasPrevious()) {
                objPrevious = null;
                break;
            }
            objPrevious = listIterator.previous();
            if (((C1291m) objPrevious).b.b.c == i) {
                break;
            }
        }
        C1291m c1291m = (C1291m) objPrevious;
        if (c1291m != null) {
            return c1291m;
        }
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "No destination with ID ", " is on the NavController's back stack. The current destination is ");
        sbV.append(g());
        throw new IllegalArgumentException(sbV.toString().toString());
    }

    public final androidx.navigation.B g() {
        C1291m c1291m = (C1291m) this.f.k();
        if (c1291m != null) {
            return c1291m.b;
        }
        return null;
    }

    public final D h() {
        D d = this.c;
        if (d == null) {
            throw new IllegalStateException("You must call setGraph() before calling getGraph()");
        }
        Intrinsics.e(d, "null cannot be cast to non-null type androidx.navigation.NavGraph");
        return d;
    }

    public final B i() {
        return this.n == null ? B.c : this.q;
    }

    public final D j() {
        androidx.navigation.B b;
        C1291m c1291m = (C1291m) this.f.k();
        if (c1291m == null || (b = c1291m.b) == null) {
            b = this.c;
            Intrinsics.d(b);
        }
        D d = b instanceof D ? (D) b : null;
        if (d != null) {
            return d;
        }
        D d2 = b.c;
        Intrinsics.d(d2);
        return d2;
    }

    public final void k(C1291m child, C1291m parent) {
        Intrinsics.checkNotNullParameter(child, "child");
        Intrinsics.checkNotNullParameter(parent, "parent");
        this.j.put(child, parent);
        LinkedHashMap linkedHashMap = this.k;
        if (linkedHashMap.get(parent) == null) {
            linkedHashMap.put(parent, new a());
        }
        Object obj = linkedHashMap.get(parent);
        Intrinsics.d(obj);
        ((a) obj).a.incrementAndGet();
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x004b  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0122  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0241  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0245  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void l(androidx.navigation.B r24, android.os.Bundle r25, androidx.navigation.K r26) {
        /*
            Method dump skipped, instructions count: 687
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.internal.j.l(androidx.navigation.B, android.os.Bundle, androidx.navigation.K):void");
    }

    public final void m(String route, androidx.navigation.K k) {
        Intrinsics.checkNotNullParameter(route, "route");
        if (this.c == null) {
            throw new IllegalArgumentException(("Cannot navigate to " + route + ". Navigation graph has not been set for NavController " + this + '.').toString());
        }
        D dJ = j();
        A aN = dJ.n(route, true, dJ);
        if (aN == null) {
            StringBuilder sbY = android.support.v4.media.session.a.y("Navigation destination that matches route ", route, " cannot be found in the navigation graph ");
            sbY.append(this.c);
            throw new IllegalArgumentException(sbY.toString());
        }
        Bundle bundle = aN.b;
        androidx.navigation.B b = aN.a;
        Bundle source = b.b(bundle);
        if (source == null) {
            V.c();
            source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
            Intrinsics.checkNotNullParameter(source, "source");
        }
        int i = androidx.navigation.B.e;
        String str = (String) b.b.f;
        String uriString = str != null ? "android-app://androidx.navigation/".concat(str) : "";
        Intrinsics.checkNotNullParameter(uriString, "uriString");
        Intrinsics.checkNotNullParameter(uriString, "uriString");
        Uri uri = Uri.parse(uriString);
        Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
        Intrinsics.checkNotNullParameter(uri, "uri");
        Intrinsics.checkNotNullParameter(uri, "uri");
        com.quizlet.data.repository.set.f request = new com.quizlet.data.repository.set.f(uri, (String) null, (String) null);
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(source, "args");
        Intent intent = new Intent();
        intent.setDataAndType(uri, null);
        intent.setAction(null);
        Intrinsics.checkNotNullParameter(source, "source");
        AbstractC3343g2.f(intent, source);
        l(b, source, k);
    }

    public final boolean n(int i, boolean z, boolean z2) {
        androidx.navigation.B b;
        C4927s c4927s = this.f;
        if (c4927s.isEmpty()) {
            return false;
        }
        ArrayList arrayList = new ArrayList();
        Iterator it2 = CollectionsKt.g0(c4927s).iterator();
        while (true) {
            if (!it2.hasNext()) {
                b = null;
                break;
            }
            b = ((C1291m) it2.next()).b;
            W wC = this.s.c(b.a);
            m mVar = b.b;
            if (z || mVar.c != i) {
                arrayList.add(wC);
            }
            if (mVar.c == i) {
                break;
            }
        }
        if (b != null) {
            return c(arrayList, b, z, z2);
        }
        int i2 = androidx.navigation.B.e;
        String message = "Ignoring popBackStack to destination " + H1.a(this.a.c, i) + " as it was not found on the current back stack";
        Intrinsics.checkNotNullParameter("NavController", "tag");
        Intrinsics.checkNotNullParameter(message, "message");
        Log.i("NavController", message);
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:46:0x00e3  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00f3 A[LOOP:0: B:6:0x0022->B:49:0x00f3, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00fa A[EDGE_INSN: B:61:0x00fa->B:51:0x00fa BREAK  A[LOOP:0: B:6:0x0022->B:49:0x00f3], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean o(java.lang.String r19, boolean r20, boolean r21) {
        /*
            Method dump skipped, instructions count: 302
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.internal.j.o(java.lang.String, boolean, boolean):boolean");
    }

    public final void p(C1291m popUpTo, boolean z, C4927s savedState) {
        C1296s c1296s;
        Z z2;
        Set set;
        Intrinsics.checkNotNullParameter(popUpTo, "popUpTo");
        Intrinsics.checkNotNullParameter(savedState, "savedState");
        C4927s c4927s = this.f;
        C1291m c1291m = (C1291m) c4927s.last();
        if (!Intrinsics.b(c1291m, popUpTo)) {
            throw new IllegalStateException(("Attempted to pop " + popUpTo.b + ", which is not the top of the back stack (" + c1291m.b + ')').toString());
        }
        G.A(c4927s);
        C1295q c1295q = (C1295q) this.t.get(this.s.c(c1291m.b.a));
        boolean z3 = true;
        if ((c1295q == null || (z2 = c1295q.f) == null || (set = (Set) ((s0) z2.a).getValue()) == null || !set.contains(c1291m)) && !this.k.containsKey(c1291m)) {
            z3 = false;
        }
        B b = c1291m.h.j.d;
        B b2 = B.c;
        if (b.a(b2)) {
            if (z) {
                c1291m.a(b2);
                savedState.addFirst(new C1292n(c1291m));
            }
            if (z3) {
                c1291m.a(b2);
            } else {
                c1291m.a(B.a);
                t(c1291m);
            }
        }
        if (z || z3 || (c1296s = this.o) == null) {
            return;
        }
        String backStackEntryId = c1291m.f;
        Intrinsics.checkNotNullParameter(backStackEntryId, "backStackEntryId");
        B0 b0 = (B0) c1296s.b.remove(backStackEntryId);
        if (b0 != null) {
            b0.a();
        }
    }

    public final ArrayList r() {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = this.t.values().iterator();
        while (it2.hasNext()) {
            Iterable iterable = (Iterable) ((s0) ((C1295q) it2.next()).f.a).getValue();
            ArrayList arrayList2 = new ArrayList();
            for (Object obj : iterable) {
                C1291m c1291m = (C1291m) obj;
                if (!arrayList.contains(c1291m) && !c1291m.h.k.a(B.d)) {
                    arrayList2.add(obj);
                }
            }
            G.u(arrayList, arrayList2);
        }
        ArrayList arrayList3 = new ArrayList();
        Iterator it3 = this.f.iterator();
        while (it3.hasNext()) {
            Object next = it3.next();
            C1291m c1291m2 = (C1291m) next;
            if (!arrayList.contains(c1291m2) && c1291m2.h.k.a(B.d)) {
                arrayList3.add(next);
            }
        }
        G.u(arrayList, arrayList3);
        ArrayList arrayList4 = new ArrayList();
        Iterator it4 = arrayList.iterator();
        while (it4.hasNext()) {
            Object next2 = it4.next();
            if (!(((C1291m) next2).b instanceof D)) {
                arrayList4.add(next2);
            }
        }
        return arrayList4;
    }

    public final boolean s(int i, Bundle bundle, androidx.navigation.K k) {
        androidx.navigation.B bH;
        C1291m c1291m;
        androidx.navigation.B b;
        int i2 = 0;
        LinkedHashMap linkedHashMap = this.l;
        if (!linkedHashMap.containsKey(Integer.valueOf(i))) {
            return false;
        }
        String str = (String) linkedHashMap.get(Integer.valueOf(i));
        Collection collectionValues = linkedHashMap.values();
        h predicate = new h(str, i2);
        Intrinsics.checkNotNullParameter(collectionValues, "<this>");
        Intrinsics.checkNotNullParameter(predicate, "predicate");
        G.x(collectionValues, predicate, true);
        C4927s c4927s = (C4927s) O.c(this.m).remove(str);
        ArrayList arrayList = new ArrayList();
        C1291m c1291m2 = (C1291m) this.f.k();
        if (c1291m2 == null || (bH = c1291m2.b) == null) {
            bH = h();
        }
        if (c4927s != null) {
            Iterator it2 = c4927s.iterator();
            while (it2.hasNext()) {
                C1292n c1292n = (C1292n) it2.next();
                androidx.navigation.B bE = e(c1292n.a.b, bH, null, true);
                d dVar = this.a.c;
                if (bE == null) {
                    int i3 = androidx.navigation.B.e;
                    throw new IllegalStateException(("Restore State failed: destination " + H1.a(dVar, c1292n.a.b) + " cannot be found from the current destination " + bH).toString());
                }
                arrayList.add(c1292n.a(dVar, bE, i(), this.o));
                bH = bE;
            }
        }
        ArrayList arrayList2 = new ArrayList();
        ArrayList arrayList3 = new ArrayList();
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            Object next = it3.next();
            if (!(((C1291m) next).b instanceof D)) {
                arrayList3.add(next);
            }
        }
        Iterator it4 = arrayList3.iterator();
        while (it4.hasNext()) {
            C1291m c1291m3 = (C1291m) it4.next();
            List list = (List) CollectionsKt.V(arrayList2);
            if (Intrinsics.b((list == null || (c1291m = (C1291m) CollectionsKt.U(list)) == null || (b = c1291m.b) == null) ? null : b.a, c1291m3.b.a)) {
                list.add(c1291m3);
            } else {
                arrayList2.add(kotlin.collections.B.k(c1291m3));
            }
        }
        F f = new F();
        Iterator it5 = arrayList2.iterator();
        while (it5.hasNext()) {
            List entries = (List) it5.next();
            W navigator = this.s.c(((C1291m) CollectionsKt.L(entries)).b.a);
            Bundle bundle2 = bundle;
            i handler = new i(f, arrayList, new H(), this, bundle2, 0);
            Intrinsics.checkNotNullParameter(navigator, "navigator");
            Intrinsics.checkNotNullParameter(entries, "entries");
            Intrinsics.checkNotNullParameter(handler, "handler");
            this.u = handler;
            navigator.d(entries, k);
            this.u = null;
            bundle = bundle2;
        }
        return f.a;
    }

    public final void t(C1291m child) {
        Intrinsics.checkNotNullParameter(child, "child");
        C1291m c1291m = (C1291m) this.j.remove(child);
        if (c1291m == null) {
            return;
        }
        LinkedHashMap linkedHashMap = this.k;
        a aVar = (a) linkedHashMap.get(c1291m);
        Integer numValueOf = aVar != null ? Integer.valueOf(aVar.a.decrementAndGet()) : null;
        if (numValueOf != null && numValueOf.intValue() == 0) {
            C1295q c1295q = (C1295q) this.t.get(this.s.c(c1291m.b.a));
            if (c1295q != null) {
                c1295q.c(c1291m);
            }
            linkedHashMap.remove(c1291m);
        }
    }

    public final void u() {
        a aVar;
        Z z;
        Set set;
        ArrayList arrayListY0 = CollectionsKt.y0(this.f);
        if (arrayListY0.isEmpty()) {
            return;
        }
        ArrayList arrayListK = kotlin.collections.B.k(((C1291m) CollectionsKt.U(arrayListY0)).b);
        ArrayList arrayList = new ArrayList();
        if (CollectionsKt.U(arrayListK) instanceof InterfaceC1286h) {
            Iterator it2 = CollectionsKt.g0(arrayListY0).iterator();
            while (it2.hasNext()) {
                androidx.navigation.B b = ((C1291m) it2.next()).b;
                arrayList.add(b);
                if (!(b instanceof InterfaceC1286h) && !(b instanceof D)) {
                    break;
                }
            }
        }
        HashMap map = new HashMap();
        for (C1291m c1291m : CollectionsKt.g0(arrayListY0)) {
            B b2 = c1291m.h.k;
            androidx.navigation.B b3 = c1291m.b;
            androidx.navigation.B b4 = (androidx.navigation.B) CollectionsKt.firstOrNull(arrayListK);
            if (b4 != null && b4.b.c == b3.b.c) {
                B b5 = B.e;
                if (b2 != b5) {
                    C1295q c1295q = (C1295q) this.t.get(this.s.c(c1291m.b.a));
                    if (Intrinsics.b((c1295q == null || (z = c1295q.f) == null || (set = (Set) ((s0) z.a).getValue()) == null) ? null : Boolean.valueOf(set.contains(c1291m)), Boolean.TRUE) || ((aVar = (a) this.k.get(c1291m)) != null && aVar.a.get() == 0)) {
                        map.put(c1291m, B.d);
                    } else {
                        map.put(c1291m, b5);
                    }
                }
                androidx.navigation.B b6 = (androidx.navigation.B) CollectionsKt.firstOrNull(arrayList);
                if (b6 != null && b6.b.c == b3.b.c) {
                    G.z(arrayList);
                }
                G.z(arrayListK);
                D d = b3.c;
                if (d != null) {
                    arrayListK.add(d);
                }
            } else if (arrayList.isEmpty() || b3.b.c != ((androidx.navigation.B) CollectionsKt.L(arrayList)).b.c) {
                c1291m.a(B.c);
            } else {
                androidx.navigation.B b7 = (androidx.navigation.B) G.z(arrayList);
                if (b2 == B.e) {
                    c1291m.a(B.d);
                } else {
                    B b8 = B.d;
                    if (b2 != b8) {
                        map.put(c1291m, b8);
                    }
                }
                D d2 = b7.c;
                if (d2 != null && !arrayList.contains(d2)) {
                    arrayList.add(d2);
                }
            }
        }
        Iterator it3 = arrayListY0.iterator();
        while (it3.hasNext()) {
            C1291m c1291m2 = (C1291m) it3.next();
            B b9 = (B) map.get(c1291m2);
            if (b9 != null) {
                c1291m2.a(b9);
            } else {
                c1291m2.h.b();
            }
        }
    }
}
