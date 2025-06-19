package androidx.compose.ui.layout;

import android.view.ViewGroup;
import androidx.compose.runtime.AbstractC0805k0;
import androidx.compose.runtime.AbstractC0827t;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.C0833w;
import androidx.compose.runtime.InterfaceC0802j;
import androidx.compose.runtime.L0;
import androidx.compose.ui.node.s0;
import androidx.compose.ui.platform.v1;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class G implements InterfaceC0802j {
    public final androidx.compose.ui.node.E a;
    public AbstractC0827t b;
    public h0 c;
    public int d;
    public int e;
    public int n;
    public int o;
    public final HashMap f = new HashMap();
    public final HashMap g = new HashMap();
    public final B h = new B(this);
    public final C0904z i = new C0904z(this);
    public final HashMap j = new HashMap();
    public final g0 k = new g0();
    public final LinkedHashMap l = new LinkedHashMap();
    public final androidx.compose.runtime.collection.b m = new androidx.compose.runtime.collection.b(new Object[16]);
    public final String p = "Asking for intrinsic measurements of SubcomposeLayout layouts is not supported. This includes components that are built on top of SubcomposeLayout, such as lazy lists, BoxWithConstraints, TabRow, etc. To mitigate this:\n- if intrinsic measurements are used to achieve 'match parent' sizing, consider replacing the parent of the component with a custom layout which controls the order in which children are measured, making intrinsic measurement not needed\n- adding a size modifier to the component, in order to fast return the queried intrinsic measurement.";

    public G(androidx.compose.ui.node.E e, h0 h0Var) {
        this.a = e;
        this.c = h0Var;
    }

    public static C0833w i(C0833w c0833w, androidx.compose.ui.node.E e, boolean z, AbstractC0827t abstractC0827t, androidx.compose.runtime.internal.d dVar) {
        if (c0833w == null || c0833w.t) {
            ViewGroup.LayoutParams layoutParams = v1.a;
            c0833w = new C0833w(abstractC0827t, new s0(e));
        }
        if (!z) {
            c0833w.m(dVar);
            return c0833w;
        }
        C0814p c0814p = c0833w.s;
        c0814p.y = 100;
        c0814p.x = true;
        c0833w.m(dVar);
        if (c0814p.E || c0814p.y != 100) {
            AbstractC0805k0.a("Cannot disable reuse from root if it was caused by other groups");
        }
        c0814p.y = -1;
        c0814p.x = false;
        return c0833w;
    }

    @Override // androidx.compose.runtime.InterfaceC0802j
    public final void a() {
        androidx.compose.ui.node.E e = this.a;
        e.l = true;
        HashMap map = this.f;
        Iterator it2 = map.values().iterator();
        while (it2.hasNext()) {
            C0833w c0833w = ((C0903y) it2.next()).c;
            if (c0833w != null) {
                c0833w.dispose();
            }
        }
        e.N();
        e.l = false;
        map.clear();
        this.g.clear();
        this.o = 0;
        this.n = 0;
        this.j.clear();
        e();
    }

    @Override // androidx.compose.runtime.InterfaceC0802j
    public final void b() {
        f(true);
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x00f0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(int r13) {
        /*
            Method dump skipped, instructions count: 257
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.layout.G.c(int):void");
    }

    @Override // androidx.compose.runtime.InterfaceC0802j
    public final void d() {
        f(false);
    }

    public final void e() {
        int i = ((androidx.compose.runtime.collection.b) ((androidx.collection.E) this.a.p()).b).c;
        HashMap map = this.f;
        if (map.size() != i) {
            throw new IllegalArgumentException(("Inconsistency between the count of nodes tracked by the state (" + map.size() + ") and the children count on the SubcomposeLayout (" + i + "). Are you trying to use the state of the disposed SubcomposeLayout?").toString());
        }
        if ((i - this.n) - this.o < 0) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i, "Incorrect state. Total children ", ". Reusable children ");
            sbV.append(this.n);
            sbV.append(". Precomposed children ");
            sbV.append(this.o);
            throw new IllegalArgumentException(sbV.toString().toString());
        }
        HashMap map2 = this.j;
        if (map2.size() == this.o) {
            return;
        }
        throw new IllegalArgumentException(("Incorrect state. Precomposed children " + this.o + ". Map size " + map2.size()).toString());
    }

    public final void f(boolean z) {
        this.o = 0;
        this.j.clear();
        androidx.compose.ui.node.E e = this.a;
        int i = ((androidx.compose.runtime.collection.b) ((androidx.collection.E) e.p()).b).c;
        if (this.n != i) {
            this.n = i;
            androidx.compose.runtime.snapshots.h hVarD = androidx.compose.runtime.snapshots.r.d();
            Function1 function1E = hVarD != null ? hVarD.e() : null;
            androidx.compose.runtime.snapshots.h hVarE = androidx.compose.runtime.snapshots.r.e(hVarD);
            for (int i2 = 0; i2 < i; i2++) {
                try {
                    androidx.compose.ui.node.E e2 = (androidx.compose.ui.node.E) ((androidx.collection.E) e.p()).get(i2);
                    C0903y c0903y = (C0903y) this.f.get(e2);
                    if (c0903y != null && ((Boolean) ((L0) c0903y.f).getValue()).booleanValue()) {
                        androidx.compose.ui.node.L l = e2.x;
                        l.r.k = 3;
                        androidx.compose.ui.node.J j = l.s;
                        if (j != null) {
                            j.i = 3;
                        }
                        if (z) {
                            C0833w c0833w = c0903y.c;
                            if (c0833w != null) {
                                c0833w.n();
                            }
                            c0903y.f = C0776c.z(Boolean.FALSE);
                        } else {
                            ((L0) c0903y.f).setValue(Boolean.FALSE);
                        }
                        c0903y.a = AbstractC0897s.a;
                    }
                } catch (Throwable th) {
                    androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
                    throw th;
                }
            }
            Unit unit = Unit.a;
            androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
            this.g.clear();
        }
        e();
    }

    public final c0 g(Object obj, Function2 function2) {
        androidx.compose.ui.node.E e = this.a;
        if (!e.E()) {
            return new E();
        }
        e();
        if (!this.g.containsKey(obj)) {
            this.l.remove(obj);
            HashMap map = this.j;
            Object objJ = map.get(obj);
            if (objJ == null) {
                objJ = j(obj);
                if (objJ != null) {
                    int iK = ((androidx.compose.runtime.collection.b) ((androidx.collection.E) e.p()).b).k(objJ);
                    int i = ((androidx.compose.runtime.collection.b) ((androidx.collection.E) e.p()).b).c;
                    e.l = true;
                    e.I(iK, i, 1);
                    e.l = false;
                    this.o++;
                } else {
                    int i2 = ((androidx.compose.runtime.collection.b) ((androidx.collection.E) e.p()).b).c;
                    androidx.compose.ui.node.E e2 = new androidx.compose.ui.node.E(2);
                    e.l = true;
                    e.y(i2, e2);
                    e.l = false;
                    this.o++;
                    objJ = e2;
                }
                map.put(obj, objJ);
            }
            h((androidx.compose.ui.node.E) objJ, obj, function2);
        }
        return new F(this, obj);
    }

    public final void h(androidx.compose.ui.node.E e, Object obj, Function2 function2) {
        boolean z;
        HashMap map = this.f;
        Object obj2 = map.get(e);
        Object obj3 = obj2;
        if (obj2 == null) {
            androidx.compose.runtime.internal.d dVar = AbstractC0887h.a;
            C0903y c0903y = new C0903y();
            c0903y.a = obj;
            c0903y.b = dVar;
            c0903y.c = null;
            c0903y.f = C0776c.z(Boolean.TRUE);
            map.put(e, c0903y);
            obj3 = c0903y;
        }
        C0903y c0903y2 = (C0903y) obj3;
        C0833w c0833w = c0903y2.c;
        if (c0833w != null) {
            synchronized (c0833w.d) {
                z = c0833w.n.e > 0;
            }
        } else {
            z = true;
        }
        if (c0903y2.b != function2 || z || c0903y2.d) {
            c0903y2.b = function2;
            androidx.compose.runtime.snapshots.h hVarD = androidx.compose.runtime.snapshots.r.d();
            Function1 function1E = hVarD != null ? hVarD.e() : null;
            androidx.compose.runtime.snapshots.h hVarE = androidx.compose.runtime.snapshots.r.e(hVarD);
            try {
                androidx.compose.ui.node.E e2 = this.a;
                e2.l = true;
                Function2 function22 = c0903y2.b;
                C0833w c0833w2 = c0903y2.c;
                AbstractC0827t abstractC0827t = this.b;
                if (abstractC0827t == null) {
                    throw new IllegalStateException("parent composition reference not set");
                }
                c0903y2.c = i(c0833w2, e, c0903y2.e, abstractC0827t, new androidx.compose.runtime.internal.d(true, -1750409193, new androidx.compose.foundation.contextmenu.i(23, c0903y2, function22)));
                c0903y2.e = false;
                e2.l = false;
                Unit unit = Unit.a;
                androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
                c0903y2.d = false;
            } catch (Throwable th) {
                androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
                throw th;
            }
        }
    }

    public final androidx.compose.ui.node.E j(Object obj) {
        HashMap map;
        int i;
        if (this.n == 0) {
            return null;
        }
        androidx.compose.ui.node.E e = this.a;
        int i2 = ((androidx.compose.runtime.collection.b) ((androidx.collection.E) e.p()).b).c - this.o;
        int i3 = i2 - this.n;
        int i4 = i2 - 1;
        int i5 = i4;
        while (true) {
            map = this.f;
            if (i5 < i3) {
                i = -1;
                break;
            }
            Object obj2 = map.get((androidx.compose.ui.node.E) ((androidx.collection.E) e.p()).get(i5));
            Intrinsics.d(obj2);
            if (Intrinsics.b(((C0903y) obj2).a, obj)) {
                i = i5;
                break;
            }
            i5--;
        }
        if (i == -1) {
            while (i4 >= i3) {
                Object obj3 = map.get((androidx.compose.ui.node.E) ((androidx.collection.E) e.p()).get(i4));
                Intrinsics.d(obj3);
                C0903y c0903y = (C0903y) obj3;
                Object obj4 = c0903y.a;
                if (obj4 == AbstractC0897s.a || this.c.c(obj, obj4)) {
                    c0903y.a = obj;
                    i5 = i4;
                    i = i5;
                    break;
                }
                i4--;
            }
            i5 = i4;
        }
        if (i == -1) {
            return null;
        }
        if (i5 != i3) {
            e.l = true;
            e.I(i5, i3, 1);
            e.l = false;
        }
        this.n--;
        androidx.compose.ui.node.E e2 = (androidx.compose.ui.node.E) ((androidx.collection.E) e.p()).get(i3);
        Object obj5 = map.get(e2);
        Intrinsics.d(obj5);
        C0903y c0903y2 = (C0903y) obj5;
        c0903y2.f = C0776c.z(Boolean.TRUE);
        c0903y2.e = true;
        c0903y2.d = true;
        return e2;
    }
}
