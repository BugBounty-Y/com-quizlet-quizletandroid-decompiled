package androidx.compose.runtime;

import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.runtime.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0810n extends AbstractC0827t {
    public final int a;
    public final boolean b;
    public final boolean c;
    public HashSet d;
    public final LinkedHashSet e = new LinkedHashSet();
    public final InterfaceC0773a0 f = new ParcelableSnapshotMutableState(androidx.compose.runtime.internal.i.e, V.d);
    public final /* synthetic */ C0814p g;

    public C0810n(C0814p c0814p, int i, boolean z, boolean z2, V v) {
        this.g = c0814p;
        this.a = i;
        this.b = z;
        this.c = z2;
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void a(C0833w c0833w, androidx.compose.runtime.internal.d dVar) {
        this.g.b.a(c0833w, dVar);
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void b(Z z) {
        this.g.b.b(z);
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void c() {
        C0814p c0814p = this.g;
        c0814p.z--;
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final boolean d() {
        return this.g.b.d();
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final boolean e() {
        return this.b;
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final boolean f() {
        return this.c;
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final InterfaceC0803j0 g() {
        return (InterfaceC0803j0) ((L0) this.f).getValue();
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final int h() {
        return this.a;
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final CoroutineContext i() {
        return this.g.b.i();
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void j(Z z) {
        this.g.b.j(z);
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void k(C0833w c0833w) {
        C0814p c0814p = this.g;
        c0814p.b.k(c0814p.g);
        c0814p.b.k(c0833w);
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void l(Z z, Y y, InterfaceC0790d interfaceC0790d) {
        this.g.b.l(z, y, interfaceC0790d);
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final Y m(Z z) {
        return this.g.b.m(z);
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void n(Set set) {
        HashSet hashSet = this.d;
        if (hashSet == null) {
            hashSet = new HashSet();
            this.d = hashSet;
        }
        hashSet.add(set);
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void o(C0814p c0814p) {
        this.e.add(c0814p);
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void p(C0833w c0833w) {
        this.g.b.p(c0833w);
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void q() {
        this.g.z++;
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void r(InterfaceC0806l interfaceC0806l) {
        HashSet hashSet = this.d;
        if (hashSet != null) {
            Iterator it2 = hashSet.iterator();
            while (it2.hasNext()) {
                Set set = (Set) it2.next();
                Intrinsics.e(interfaceC0806l, "null cannot be cast to non-null type androidx.compose.runtime.ComposerImpl");
                set.remove(((C0814p) interfaceC0806l).c);
            }
        }
        kotlin.jvm.internal.O.a(this.e).remove(interfaceC0806l);
    }

    @Override // androidx.compose.runtime.AbstractC0827t
    public final void s(C0833w c0833w) {
        this.g.b.s(c0833w);
    }

    public final void t() {
        LinkedHashSet<C0814p> linkedHashSet = this.e;
        if (linkedHashSet.isEmpty()) {
            return;
        }
        HashSet hashSet = this.d;
        if (hashSet != null) {
            for (C0814p c0814p : linkedHashSet) {
                Iterator it2 = hashSet.iterator();
                while (it2.hasNext()) {
                    ((Set) it2.next()).remove(c0814p.c);
                }
            }
        }
        linkedHashSet.clear();
    }
}
