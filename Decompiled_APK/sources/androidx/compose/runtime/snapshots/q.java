package androidx.compose.runtime.snapshots;

import androidx.compose.runtime.AbstractC0805k0;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.RandomAccess;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class q implements z, List, RandomAccess, kotlin.jvm.internal.markers.c {
    public p a;

    public q() {
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.j jVar = androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.j.c;
        h hVarK = m.k();
        p pVar = new p(hVarK.g(), jVar);
        if (!(hVarK instanceof C0823c)) {
            pVar.b = new p(1, jVar);
        }
        this.a = pVar;
    }

    public static boolean e(p pVar, int i, androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar, boolean z) {
        boolean z2;
        synchronized (r.a) {
            try {
                int i2 = pVar.d;
                if (i2 == i) {
                    pVar.c = cVar;
                    z2 = true;
                    if (z) {
                        pVar.e++;
                    }
                    pVar.d = i2 + 1;
                } else {
                    z2 = false;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return z2;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final void a(B b) {
        b.b = this.a;
        this.a = (p) b;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean add(Object obj) {
        int i;
        androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar;
        h hVarK;
        boolean zE;
        do {
            synchronized (r.a) {
                p pVar = this.a;
                Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                p pVar2 = (p) m.i(pVar);
                i = pVar2.d;
                cVar = pVar2.c;
                Unit unit = Unit.a;
            }
            Intrinsics.d(cVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.c cVarAdd = cVar.add(obj);
            if (cVarAdd.equals(cVar)) {
                return false;
            }
            p pVar3 = this.a;
            Intrinsics.e(pVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
            synchronized (m.b) {
                hVarK = m.k();
                zE = e((p) m.w(pVar3, this, hVarK), i, cVarAdd, true);
            }
            m.n(hVarK, this);
        } while (!zE);
        return true;
    }

    @Override // java.util.List
    public final boolean addAll(int i, Collection collection) {
        return j(new androidx.compose.foundation.lazy.u(i, collection));
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final B b() {
        return this.a;
    }

    @Override // java.util.List, java.util.Collection
    public final void clear() {
        h hVarK;
        p pVar = this.a;
        Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
        synchronized (m.b) {
            hVarK = m.k();
            p pVar2 = (p) m.w(pVar, this, hVarK);
            synchronized (r.a) {
                pVar2.c = androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.j.c;
                pVar2.d++;
                pVar2.e++;
            }
        }
        m.n(hVarK, this);
    }

    @Override // java.util.List, java.util.Collection
    public final boolean contains(Object obj) {
        return ((androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.c) h().c).contains(obj);
    }

    @Override // java.util.List, java.util.Collection
    public final boolean containsAll(Collection collection) {
        return ((androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.c) h().c).containsAll(collection);
    }

    @Override // java.util.List
    public final Object get(int i) {
        return h().c.get(i);
    }

    public final p h() {
        p pVar = this.a;
        Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
        return (p) m.t(pVar, this);
    }

    public final int i() {
        p pVar = this.a;
        Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
        return ((p) m.i(pVar)).e;
    }

    @Override // java.util.List
    public final int indexOf(Object obj) {
        return h().c.indexOf(obj);
    }

    @Override // java.util.List, java.util.Collection
    public final boolean isEmpty() {
        return h().c.isEmpty();
    }

    @Override // java.util.List, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        return listIterator();
    }

    public final boolean j(Function1 function1) {
        int i;
        androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar;
        Object objInvoke;
        h hVarK;
        boolean zE;
        do {
            synchronized (r.a) {
                p pVar = this.a;
                Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                p pVar2 = (p) m.i(pVar);
                i = pVar2.d;
                cVar = pVar2.c;
                Unit unit = Unit.a;
            }
            Intrinsics.d(cVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.g gVarBuilder = cVar.builder();
            objInvoke = function1.invoke(gVarBuilder);
            androidx.compose.runtime.external.kotlinx.collections.immutable.c cVarE = gVarBuilder.e();
            if (Intrinsics.b(cVarE, cVar)) {
                break;
            }
            p pVar3 = this.a;
            Intrinsics.e(pVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
            synchronized (m.b) {
                hVarK = m.k();
                zE = e((p) m.w(pVar3, this, hVarK), i, cVarE, true);
            }
            m.n(hVarK, this);
        } while (!zE);
        return ((Boolean) objInvoke).booleanValue();
    }

    @Override // java.util.List
    public final int lastIndexOf(Object obj) {
        return h().c.lastIndexOf(obj);
    }

    @Override // java.util.List
    public final ListIterator listIterator() {
        return new w(this, 0);
    }

    @Override // java.util.List
    public final Object remove(int i) {
        int i2;
        androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar;
        h hVarK;
        boolean zE;
        Object obj = get(i);
        do {
            synchronized (r.a) {
                p pVar = this.a;
                Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                p pVar2 = (p) m.i(pVar);
                i2 = pVar2.d;
                cVar = pVar2.c;
                Unit unit = Unit.a;
            }
            Intrinsics.d(cVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.c cVarY = cVar.y(i);
            if (cVarY.equals(cVar)) {
                break;
            }
            p pVar3 = this.a;
            Intrinsics.e(pVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
            synchronized (m.b) {
                hVarK = m.k();
                zE = e((p) m.w(pVar3, this, hVarK), i2, cVarY, true);
            }
            m.n(hVarK, this);
        } while (!zE);
        return obj;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean removeAll(Collection collection) {
        int i;
        androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar;
        h hVarK;
        boolean zE;
        int i2 = 0;
        do {
            synchronized (r.a) {
                p pVar = this.a;
                Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                p pVar2 = (p) m.i(pVar);
                i = pVar2.d;
                cVar = pVar2.c;
                Unit unit = Unit.a;
            }
            Intrinsics.d(cVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.c cVarY = ((androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.c) cVar).Y(new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.b(i2, collection));
            if (Intrinsics.b(cVarY, cVar)) {
                return false;
            }
            p pVar3 = this.a;
            Intrinsics.e(pVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
            synchronized (m.b) {
                hVarK = m.k();
                zE = e((p) m.w(pVar3, this, hVarK), i, cVarY, true);
            }
            m.n(hVarK, this);
        } while (!zE);
        return true;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean retainAll(Collection collection) {
        return j(new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.b(2, collection));
    }

    @Override // java.util.List
    public final Object set(int i, Object obj) {
        int i2;
        androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar;
        h hVarK;
        boolean zE;
        Object obj2 = get(i);
        do {
            synchronized (r.a) {
                p pVar = this.a;
                Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                p pVar2 = (p) m.i(pVar);
                i2 = pVar2.d;
                cVar = pVar2.c;
                Unit unit = Unit.a;
            }
            Intrinsics.d(cVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar2 = cVar.set(i, obj);
            if (cVar2.equals(cVar)) {
                break;
            }
            p pVar3 = this.a;
            Intrinsics.e(pVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
            synchronized (m.b) {
                hVarK = m.k();
                zE = e((p) m.w(pVar3, this, hVarK), i2, cVar2, false);
            }
            m.n(hVarK, this);
        } while (!zE);
        return obj2;
    }

    @Override // java.util.List, java.util.Collection
    public final int size() {
        return h().c.size();
    }

    @Override // java.util.List
    public final List subList(int i, int i2) {
        if (!(i >= 0 && i <= i2 && i2 <= size())) {
            AbstractC0805k0.a("fromIndex or toIndex are out of bounds");
        }
        return new D(this, i, i2);
    }

    @Override // java.util.List, java.util.Collection
    public final Object[] toArray() {
        return AbstractC4958q.a(this);
    }

    public final String toString() {
        p pVar = this.a;
        Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
        return "SnapshotStateList(value=" + ((p) m.i(pVar)).c + ")@" + hashCode();
    }

    @Override // java.util.List, java.util.Collection
    public final boolean addAll(Collection collection) {
        int i;
        androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar;
        h hVarK;
        boolean zE;
        do {
            synchronized (r.a) {
                p pVar = this.a;
                Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                p pVar2 = (p) m.i(pVar);
                i = pVar2.d;
                cVar = pVar2.c;
                Unit unit = Unit.a;
            }
            Intrinsics.d(cVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.c cVarAddAll = cVar.addAll(collection);
            if (Intrinsics.b(cVarAddAll, cVar)) {
                return false;
            }
            p pVar3 = this.a;
            Intrinsics.e(pVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
            synchronized (m.b) {
                hVarK = m.k();
                zE = e((p) m.w(pVar3, this, hVarK), i, cVarAddAll, true);
            }
            m.n(hVarK, this);
        } while (!zE);
        return true;
    }

    @Override // java.util.List
    public final ListIterator listIterator(int i) {
        return new w(this, i);
    }

    @Override // java.util.List, java.util.Collection
    public final Object[] toArray(Object[] objArr) {
        return AbstractC4958q.b(this, objArr);
    }

    @Override // java.util.List
    public final void add(int i, Object obj) {
        int i2;
        androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar;
        h hVarK;
        boolean zE;
        do {
            synchronized (r.a) {
                p pVar = this.a;
                Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                p pVar2 = (p) m.i(pVar);
                i2 = pVar2.d;
                cVar = pVar2.c;
                Unit unit = Unit.a;
            }
            Intrinsics.d(cVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.c cVarAdd = cVar.add(i, obj);
            if (cVarAdd.equals(cVar)) {
                return;
            }
            p pVar3 = this.a;
            Intrinsics.e(pVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
            synchronized (m.b) {
                hVarK = m.k();
                zE = e((p) m.w(pVar3, this, hVarK), i2, cVarAdd, true);
            }
            m.n(hVarK, this);
        } while (!zE);
    }

    @Override // java.util.List, java.util.Collection
    public final boolean remove(Object obj) {
        int i;
        androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar;
        h hVarK;
        boolean zE;
        do {
            synchronized (r.a) {
                p pVar = this.a;
                Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                p pVar2 = (p) m.i(pVar);
                i = pVar2.d;
                cVar = pVar2.c;
                Unit unit = Unit.a;
            }
            Intrinsics.d(cVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.c cVar2 = (androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.c) cVar;
            int iIndexOf = cVar2.indexOf(obj);
            androidx.compose.runtime.external.kotlinx.collections.immutable.c cVarY = cVar2;
            if (iIndexOf != -1) {
                cVarY = cVar2.y(iIndexOf);
            }
            if (cVarY.equals(cVar)) {
                return false;
            }
            p pVar3 = this.a;
            Intrinsics.e(pVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
            synchronized (m.b) {
                hVarK = m.k();
                zE = e((p) m.w(pVar3, this, hVarK), i, cVarY, true);
            }
            m.n(hVarK, this);
        } while (!zE);
        return true;
    }
}
