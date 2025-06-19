package androidx.compose.runtime;

import android.util.Log;
import androidx.compose.animation.core.C0242g;
import androidx.compose.runtime.snapshots.C0824d;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.RandomAccess;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.InterfaceC5026k;

/* renamed from: androidx.compose.runtime.v0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0832v0 extends AbstractC0827t {
    public static final kotlinx.coroutines.flow.s0 y = kotlinx.coroutines.flow.e0.c(androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.b.e);
    public static final AtomicReference z = new AtomicReference(Boolean.FALSE);
    public long a;
    public final C0794f b;
    public final Object c;
    public InterfaceC5025j0 d;
    public Throwable e;
    public final ArrayList f;
    public Object g;
    public androidx.collection.J h;
    public final androidx.compose.runtime.collection.b i;
    public final ArrayList j;
    public final ArrayList k;
    public final androidx.collection.I l;
    public final com.quizlet.data.repository.activitycenter.b m;
    public final androidx.collection.I n;
    public final androidx.collection.I o;
    public ArrayList p;
    public LinkedHashSet q;
    public C5028l r;
    public com.airbnb.lottie.network.c s;
    public boolean t;
    public final kotlinx.coroutines.flow.s0 u;
    public final C5027k0 v;
    public final CoroutineContext w;
    public final V x;

    public C0832v0(CoroutineContext coroutineContext) {
        C0794f c0794f = new C0794f(new androidx.compose.animation.core.K(this, 25));
        this.b = c0794f;
        this.c = new Object();
        this.f = new ArrayList();
        this.h = new androidx.collection.J();
        this.i = new androidx.compose.runtime.collection.b(new C0833w[16]);
        this.j = new ArrayList();
        this.k = new ArrayList();
        this.l = new androidx.collection.I();
        this.m = new com.quizlet.data.repository.activitycenter.b(3);
        this.n = new androidx.collection.I();
        this.o = new androidx.collection.I();
        this.u = kotlinx.coroutines.flow.e0.c(EnumC0817q0.c);
        new AtomicReference(androidx.compose.runtime.internal.e.b);
        C5027k0 c5027k0 = new C5027k0((InterfaceC5025j0) coroutineContext.get(C5023i0.a));
        c5027k0.Q(new C0775b0(this, 1));
        this.v = c5027k0;
        this.w = coroutineContext.plus(c0794f).plus(c5027k0);
        this.x = new V(9);
    }

    public static final void D(ArrayList arrayList, C0832v0 c0832v0, C0833w c0833w) {
        arrayList.clear();
        synchronized (c0832v0.c) {
            try {
                Iterator it2 = c0832v0.k.iterator();
                while (it2.hasNext()) {
                    Z z2 = (Z) it2.next();
                    if (z2.c.equals(c0833w)) {
                        arrayList.add(z2);
                        it2.remove();
                    }
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static final C0833w t(C0832v0 c0832v0, C0833w c0833w, androidx.collection.J j) {
        LinkedHashSet linkedHashSet;
        C0824d c0824dC;
        c0832v0.getClass();
        if (!c0833w.s.E && !c0833w.t && ((linkedHashSet = c0832v0.q) == null || !linkedHashSet.contains(c0833w))) {
            C0775b0 c0775b0 = new C0775b0(c0833w, 2);
            androidx.compose.foundation.text.selection.n0 n0Var = new androidx.compose.foundation.text.selection.n0(14, c0833w, j);
            androidx.compose.runtime.snapshots.h hVarK = androidx.compose.runtime.snapshots.m.k();
            C0824d c0824d = hVarK instanceof C0824d ? (C0824d) hVarK : null;
            if (c0824d == null || (c0824dC = c0824d.C(c0775b0, n0Var)) == null) {
                throw new IllegalStateException("Cannot create a mutable snapshot of an read-only snapshot");
            }
            try {
                androidx.compose.runtime.snapshots.h hVarJ = c0824dC.j();
                if (j != null) {
                    try {
                        if (j.h()) {
                            C0242g c0242g = new C0242g(17, j, c0833w);
                            C0814p c0814p = c0833w.s;
                            if (c0814p.E) {
                                r.c("Preparing a composition while composing is not supported");
                            }
                            c0814p.E = true;
                            try {
                                c0242g.invoke();
                                c0814p.E = false;
                            } catch (Throwable th) {
                                c0814p.E = false;
                                throw th;
                            }
                        }
                    } catch (Throwable th2) {
                        androidx.compose.runtime.snapshots.h.q(hVarJ);
                        throw th2;
                    }
                }
                boolean zW = c0833w.w();
                androidx.compose.runtime.snapshots.h.q(hVarJ);
                if (zW) {
                    return c0833w;
                }
            } finally {
                v(c0824dC);
            }
        }
        return null;
    }

    public static final boolean u(C0832v0 c0832v0) {
        List listB;
        boolean z2 = true;
        synchronized (c0832v0.c) {
            if (c0832v0.h.g()) {
                if (c0832v0.i.c == 0 && !c0832v0.z()) {
                    z2 = false;
                }
                return z2;
            }
            androidx.compose.runtime.collection.e elements = new androidx.compose.runtime.collection.e(c0832v0.h);
            c0832v0.h = new androidx.collection.J();
            synchronized (c0832v0.c) {
                listB = c0832v0.B();
            }
            try {
                int size = listB.size();
                for (int i = 0; i < size; i++) {
                    ((C0833w) listB.get(i)).x(elements);
                    if (((EnumC0817q0) c0832v0.u.getValue()).compareTo(EnumC0817q0.b) <= 0) {
                        break;
                    }
                }
                synchronized (c0832v0.c) {
                    c0832v0.h = new androidx.collection.J();
                    Unit unit = Unit.a;
                }
                synchronized (c0832v0.c) {
                    if (c0832v0.y() != null) {
                        throw new IllegalStateException("called outside of runRecomposeAndApplyChanges");
                    }
                    if (c0832v0.i.c == 0 && !c0832v0.z()) {
                        z2 = false;
                    }
                }
                return z2;
            } catch (Throwable th) {
                synchronized (c0832v0.c) {
                    androidx.collection.J j = c0832v0.h;
                    j.getClass();
                    Intrinsics.checkNotNullParameter(elements, "elements");
                    Intrinsics.checkNotNullParameter(elements, "elements");
                    for (Object obj : elements) {
                        j.b[j.d(obj)] = obj;
                    }
                    throw th;
                }
            }
        }
    }

    public static void v(C0824d c0824d) {
        try {
            if (c0824d.w() instanceof androidx.compose.runtime.snapshots.i) {
                throw new IllegalStateException("Unsupported concurrent change during composition. A state object was modified by composition as well as being modified outside composition.");
            }
        } finally {
            c0824d.c();
        }
    }

    public static final void x(C0832v0 c0832v0, Z z2, Z z3) {
        ArrayList arrayList = z3.h;
        if (arrayList != null) {
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                Z z4 = (Z) arrayList.get(i);
                com.quizlet.data.repository.activitycenter.b bVar = c0832v0.m;
                X x = z4.a;
                androidx.compose.runtime.collection.a.a((androidx.collection.I) bVar.b, x, new C0777c0(z4, z2));
                androidx.compose.runtime.collection.a.a((androidx.collection.I) bVar.c, z2, x);
                x(c0832v0, z2, z4);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x001d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean A() {
        /*
            r2 = this;
            java.lang.Object r0 = r2.c
            monitor-enter(r0)
            androidx.collection.J r1 = r2.h     // Catch: java.lang.Throwable -> L1b
            boolean r1 = r1.h()     // Catch: java.lang.Throwable -> L1b
            if (r1 != 0) goto L1d
            androidx.compose.runtime.collection.b r1 = r2.i     // Catch: java.lang.Throwable -> L1b
            int r1 = r1.c     // Catch: java.lang.Throwable -> L1b
            if (r1 == 0) goto L12
            goto L1d
        L12:
            boolean r1 = r2.z()     // Catch: java.lang.Throwable -> L1b
            if (r1 == 0) goto L19
            goto L1d
        L19:
            r1 = 0
            goto L1e
        L1b:
            r1 = move-exception
            goto L20
        L1d:
            r1 = 1
        L1e:
            monitor-exit(r0)
            return r1
        L20:
            monitor-exit(r0)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0832v0.A():boolean");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r0v7 */
    /* JADX WARN: Type inference failed for: r0v8 */
    public final List B() {
        Object obj = this.g;
        ?? r0 = obj;
        if (obj == null) {
            ArrayList arrayList = this.f;
            RandomAccess arrayList2 = arrayList.isEmpty() ? kotlin.collections.K.a : new ArrayList(arrayList);
            this.g = arrayList2;
            r0 = arrayList2;
        }
        return r0;
    }

    public final void C(C0833w c0833w) {
        synchronized (this.c) {
            ArrayList arrayList = this.k;
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                if (((Z) arrayList.get(i)).c.equals(c0833w)) {
                    Unit unit = Unit.a;
                    ArrayList arrayList2 = new ArrayList();
                    D(arrayList2, this, c0833w);
                    while (!arrayList2.isEmpty()) {
                        E(arrayList2, null);
                        D(arrayList2, this, c0833w);
                    }
                    return;
                }
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:62:0x015c, code lost:
    
        r0 = r11.size();
        r4 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x0161, code lost:
    
        if (r4 >= r0) goto L132;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x016b, code lost:
    
        if (((kotlin.Pair) r11.get(r4)).b == null) goto L131;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x016d, code lost:
    
        r4 = r4 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x0170, code lost:
    
        r0 = new java.util.ArrayList(r11.size());
        r4 = r11.size();
        r5 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x017e, code lost:
    
        if (r5 >= r4) goto L133;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x0180, code lost:
    
        r9 = (kotlin.Pair) r11.get(r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x0188, code lost:
    
        if (r9.b != null) goto L74;
     */
    /* JADX WARN: Code restructure failed: missing block: B:71:0x018a, code lost:
    
        r9 = (androidx.compose.runtime.Z) r9.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x0191, code lost:
    
        r9 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x0192, code lost:
    
        if (r9 == null) goto L135;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x0194, code lost:
    
        r0.add(r9);
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x0197, code lost:
    
        r5 = r5 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x019a, code lost:
    
        r4 = r17.c;
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x019c, code lost:
    
        monitor-enter(r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x019d, code lost:
    
        kotlin.collections.G.u(r17.k, r0);
        r0 = kotlin.Unit.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x01a4, code lost:
    
        monitor-exit(r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x01a5, code lost:
    
        r0 = new java.util.ArrayList(r11.size());
        r4 = r11.size();
        r5 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x01b3, code lost:
    
        if (r5 >= r4) goto L136;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x01b5, code lost:
    
        r9 = r11.get(r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x01be, code lost:
    
        if (((kotlin.Pair) r9).b == null) goto L138;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x01c0, code lost:
    
        r0.add(r9);
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x01c3, code lost:
    
        r5 = r5 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x01c6, code lost:
    
        r11 = r0;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.List E(java.util.List r18, androidx.collection.J r19) {
        /*
            Method dump skipped, instructions count: 504
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0832v0.E(java.util.List, androidx.collection.J):java.util.List");
    }

    public final void F(Throwable th, C0833w c0833w) throws Throwable {
        int i = 8;
        if (!((Boolean) z.get()).booleanValue() || (th instanceof ComposeRuntimeError)) {
            synchronized (this.c) {
                com.airbnb.lottie.network.c cVar = this.s;
                if (cVar != null) {
                    throw ((Throwable) cVar.b);
                }
                this.s = new com.airbnb.lottie.network.c(th, i);
                Unit unit = Unit.a;
            }
            throw th;
        }
        synchronized (this.c) {
            Log.e("ComposeInternal", "Error was captured in composition while live edit was enabled.", th);
            this.j.clear();
            this.i.i();
            this.h = new androidx.collection.J();
            this.k.clear();
            this.l.a();
            this.n.a();
            this.s = new com.airbnb.lottie.network.c(th, i);
            if (c0833w != null) {
                G(c0833w);
            }
            y();
        }
    }

    public final void G(C0833w c0833w) {
        ArrayList arrayList = this.p;
        if (arrayList == null) {
            arrayList = new ArrayList();
            this.p = arrayList;
        }
        if (!arrayList.contains(c0833w)) {
            arrayList.add(c0833w);
        }
        if (this.f.remove(c0833w)) {
            this.g = null;
        }
    }

    public final Object H(kotlin.coroutines.jvm.internal.i iVar) throws Throwable {
        Object objJ = kotlinx.coroutines.E.J(this.b, new C0828t0(this, new C0830u0(this, null), C0776c.r(iVar.getContext()), null), iVar);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objJ != aVar) {
            objJ = Unit.a;
        }
        return objJ == aVar ? objJ : Unit.a;
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void a(C0833w c0833w, androidx.compose.runtime.internal.d dVar) throws Throwable {
        C0824d c0824dC;
        boolean z2 = c0833w.s.E;
        try {
            C0775b0 c0775b0 = new C0775b0(c0833w, 2);
            androidx.compose.foundation.text.selection.n0 n0Var = new androidx.compose.foundation.text.selection.n0(14, c0833w, null);
            androidx.compose.runtime.snapshots.h hVarK = androidx.compose.runtime.snapshots.m.k();
            C0824d c0824d = hVarK instanceof C0824d ? (C0824d) hVarK : null;
            if (c0824d == null || (c0824dC = c0824d.C(c0775b0, n0Var)) == null) {
                throw new IllegalStateException("Cannot create a mutable snapshot of an read-only snapshot");
            }
            try {
                androidx.compose.runtime.snapshots.h hVarJ = c0824dC.j();
                try {
                    c0833w.l(dVar);
                    Unit unit = Unit.a;
                    if (!z2) {
                        androidx.compose.runtime.snapshots.m.k().m();
                    }
                    synchronized (this.c) {
                        if (((EnumC0817q0) this.u.getValue()).compareTo(EnumC0817q0.b) > 0 && !B().contains(c0833w)) {
                            this.f.add(c0833w);
                            this.g = null;
                        }
                    }
                    try {
                        C(c0833w);
                        try {
                            c0833w.g();
                            c0833w.i();
                            if (z2) {
                                return;
                            }
                            androidx.compose.runtime.snapshots.m.k().m();
                        } catch (Throwable th) {
                            F(th, null);
                        }
                    } catch (Throwable th2) {
                        F(th2, c0833w);
                    }
                } finally {
                    androidx.compose.runtime.snapshots.h.q(hVarJ);
                }
            } finally {
                v(c0824dC);
            }
        } catch (Throwable th3) {
            F(th3, c0833w);
        }
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void b(Z z2) {
        synchronized (this.c) {
            try {
                androidx.compose.runtime.collection.a.a(this.l, z2.a, z2);
                if (z2.h != null) {
                    x(this, z2, z2);
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final boolean d() {
        return ((Boolean) z.get()).booleanValue();
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final boolean e() {
        return false;
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final boolean f() {
        return false;
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final int h() {
        return 1000;
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final CoroutineContext i() {
        return this.w;
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void j(Z z2) {
        InterfaceC5026k interfaceC5026kY;
        synchronized (this.c) {
            this.k.add(z2);
            interfaceC5026kY = y();
        }
        if (interfaceC5026kY != null) {
            kotlin.p pVar = kotlin.r.b;
            ((C5028l) interfaceC5026kY).resumeWith(Unit.a);
        }
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void k(C0833w c0833w) {
        InterfaceC5026k interfaceC5026kY;
        synchronized (this.c) {
            if (this.i.j(c0833w)) {
                interfaceC5026kY = null;
            } else {
                this.i.b(c0833w);
                interfaceC5026kY = y();
            }
        }
        if (interfaceC5026kY != null) {
            kotlin.p pVar = kotlin.r.b;
            ((C5028l) interfaceC5026kY).resumeWith(Unit.a);
        }
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void l(Z z2, Y y2, InterfaceC0790d interfaceC0790d) {
        androidx.collection.G g;
        boolean z3;
        boolean z4;
        boolean z5 = true;
        synchronized (this.c) {
            try {
                this.n.j(z2, y2);
                Object objF = this.o.f(z2);
                if (objF == null) {
                    g = androidx.collection.P.b;
                    Intrinsics.e(g, "null cannot be cast to non-null type androidx.collection.ObjectList<E of androidx.collection.ObjectListKt.emptyObjectList>");
                } else if (objF instanceof androidx.collection.G) {
                    g = (androidx.collection.G) objF;
                } else {
                    Object[] objArr = androidx.collection.P.a;
                    g = new androidx.collection.G(1);
                    g.a(objF);
                }
                if (g.b != 0) {
                    androidx.collection.I iB = y2.b(interfaceC0790d, g);
                    Object[] objArr2 = iB.b;
                    Object[] objArr3 = iB.c;
                    long[] jArr = iB.a;
                    int length = jArr.length - 2;
                    if (length >= 0) {
                        int i = 0;
                        while (true) {
                            long j = jArr[i];
                            if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                                int i2 = 8 - ((~(i - length)) >>> 31);
                                int i3 = 0;
                                while (i3 < i2) {
                                    if ((255 & j) < 128) {
                                        int i4 = (i << 3) + i3;
                                        z4 = z5;
                                        this.n.j((Z) objArr2[i4], (Y) objArr3[i4]);
                                    } else {
                                        z4 = z5;
                                    }
                                    j >>= 8;
                                    i3++;
                                    z5 = z4;
                                }
                                z3 = z5;
                                if (i2 != 8) {
                                    break;
                                }
                            } else {
                                z3 = z5;
                            }
                            if (i == length) {
                                break;
                            }
                            i++;
                            z5 = z3;
                        }
                    }
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final Y m(Z z2) {
        Y y2;
        synchronized (this.c) {
            y2 = (Y) this.n.h(z2);
        }
        return y2;
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void n(Set set) {
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void p(C0833w c0833w) {
        synchronized (this.c) {
            try {
                LinkedHashSet linkedHashSet = this.q;
                if (linkedHashSet == null) {
                    linkedHashSet = new LinkedHashSet();
                    this.q = linkedHashSet;
                }
                linkedHashSet.add(c0833w);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void s(C0833w c0833w) {
        synchronized (this.c) {
            if (this.f.remove(c0833w)) {
                this.g = null;
            }
            this.i.n(c0833w);
            this.j.remove(c0833w);
            Unit unit = Unit.a;
        }
    }

    public final void w() {
        synchronized (this.c) {
            try {
                if (((EnumC0817q0) this.u.getValue()).compareTo(EnumC0817q0.e) >= 0) {
                    kotlinx.coroutines.flow.s0 s0Var = this.u;
                    EnumC0817q0 enumC0817q0 = EnumC0817q0.b;
                    s0Var.getClass();
                    s0Var.m(null, enumC0817q0);
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
        this.v.j(null);
    }

    public final InterfaceC5026k y() {
        EnumC0817q0 enumC0817q0;
        kotlinx.coroutines.flow.s0 s0Var = this.u;
        int iCompareTo = ((EnumC0817q0) s0Var.getValue()).compareTo(EnumC0817q0.b);
        ArrayList arrayList = this.k;
        ArrayList arrayList2 = this.j;
        androidx.compose.runtime.collection.b bVar = this.i;
        if (iCompareTo <= 0) {
            this.f.clear();
            this.g = kotlin.collections.K.a;
            this.h = new androidx.collection.J();
            bVar.i();
            arrayList2.clear();
            arrayList.clear();
            this.p = null;
            C5028l c5028l = this.r;
            if (c5028l != null) {
                c5028l.b(null);
            }
            this.r = null;
            this.s = null;
            return null;
        }
        if (this.s != null) {
            enumC0817q0 = EnumC0817q0.c;
        } else if (this.d == null) {
            this.h = new androidx.collection.J();
            bVar.i();
            enumC0817q0 = z() ? EnumC0817q0.d : EnumC0817q0.c;
        } else {
            enumC0817q0 = (bVar.c == 0 && !this.h.h() && arrayList2.isEmpty() && arrayList.isEmpty() && !z()) ? EnumC0817q0.e : EnumC0817q0.f;
        }
        s0Var.getClass();
        s0Var.m(null, enumC0817q0);
        if (enumC0817q0 != EnumC0817q0.f) {
            return null;
        }
        C5028l c5028l2 = this.r;
        this.r = null;
        return c5028l2;
    }

    public final boolean z() {
        return (this.t || this.b.f.get() == 0) ? false : true;
    }
}
