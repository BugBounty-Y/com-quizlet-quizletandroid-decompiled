package androidx.compose.runtime.snapshots;

import androidx.compose.runtime.AbstractC0805k0;
import java.util.Collection;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import kotlin.Unit;
import kotlin.collections.P;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.H;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class D implements List, kotlin.jvm.internal.markers.c {
    public final q a;
    public final int b;
    public int c;
    public int d;

    public D(q qVar, int i, int i2) {
        this.a = qVar;
        this.b = i;
        this.c = qVar.i();
        this.d = i2 - i;
    }

    public final void a() {
        if (this.a.i() != this.c) {
            throw new ConcurrentModificationException();
        }
    }

    @Override // java.util.List, java.util.Collection
    public final boolean add(Object obj) {
        a();
        int i = this.b + this.d;
        q qVar = this.a;
        qVar.add(i, obj);
        this.d++;
        this.c = qVar.i();
        return true;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean addAll(Collection collection) {
        return addAll(this.d, collection);
    }

    @Override // java.util.List, java.util.Collection
    public final void clear() {
        int i;
        androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar;
        h hVarK;
        boolean zE;
        if (this.d > 0) {
            a();
            q qVar = this.a;
            int i2 = this.b;
            int i3 = this.d + i2;
            do {
                synchronized (r.a) {
                    p pVar = qVar.a;
                    Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                    p pVar2 = (p) m.i(pVar);
                    i = pVar2.d;
                    cVar = pVar2.c;
                    Unit unit = Unit.a;
                }
                Intrinsics.d(cVar);
                androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.g gVarBuilder = cVar.builder();
                gVarBuilder.subList(i2, i3).clear();
                androidx.compose.runtime.external.kotlinx.collections.immutable.c cVarE = gVarBuilder.e();
                if (Intrinsics.b(cVarE, cVar)) {
                    break;
                }
                p pVar3 = qVar.a;
                Intrinsics.e(pVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                synchronized (m.b) {
                    hVarK = m.k();
                    zE = q.e((p) m.w(pVar3, qVar, hVarK), i, cVarE, true);
                }
                m.n(hVarK, qVar);
            } while (!zE);
            this.d = 0;
            this.c = this.a.i();
        }
    }

    @Override // java.util.List, java.util.Collection
    public final boolean contains(Object obj) {
        return indexOf(obj) >= 0;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean containsAll(Collection collection) {
        Collection collection2 = collection;
        if ((collection2 instanceof Collection) && collection2.isEmpty()) {
            return true;
        }
        Iterator it2 = collection2.iterator();
        while (it2.hasNext()) {
            if (!contains(it2.next())) {
                return false;
            }
        }
        return true;
    }

    @Override // java.util.List
    public final Object get(int i) {
        a();
        r.a(i, this.d);
        return this.a.get(this.b + i);
    }

    @Override // java.util.List
    public final int indexOf(Object obj) {
        a();
        int i = this.d;
        int i2 = this.b;
        Iterator it2 = kotlin.ranges.l.h(i2, i + i2).iterator();
        while (it2.hasNext()) {
            int iNextInt = ((P) it2).nextInt();
            if (Intrinsics.b(obj, this.a.get(iNextInt))) {
                return iNextInt - i2;
            }
        }
        return -1;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean isEmpty() {
        return this.d == 0;
    }

    @Override // java.util.List, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        return listIterator(0);
    }

    @Override // java.util.List
    public final int lastIndexOf(Object obj) {
        a();
        int i = this.d;
        int i2 = this.b;
        for (int i3 = (i + i2) - 1; i3 >= i2; i3--) {
            if (Intrinsics.b(obj, this.a.get(i3))) {
                return i3 - i2;
            }
        }
        return -1;
    }

    @Override // java.util.List
    public final ListIterator listIterator() {
        return listIterator(0);
    }

    @Override // java.util.List, java.util.Collection
    public final boolean remove(Object obj) {
        int iIndexOf = indexOf(obj);
        if (iIndexOf < 0) {
            return false;
        }
        remove(iIndexOf);
        return true;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean removeAll(Collection collection) {
        Iterator it2 = collection.iterator();
        while (true) {
            boolean z = false;
            while (it2.hasNext()) {
                if (remove(it2.next()) || z) {
                    z = true;
                }
            }
            return z;
        }
    }

    @Override // java.util.List, java.util.Collection
    public final boolean retainAll(Collection collection) {
        int i;
        androidx.compose.runtime.external.kotlinx.collections.immutable.c cVar;
        h hVarK;
        boolean zE;
        a();
        q qVar = this.a;
        int i2 = this.b;
        int i3 = this.d + i2;
        int size = qVar.size();
        do {
            synchronized (r.a) {
                p pVar = qVar.a;
                Intrinsics.e(pVar, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
                p pVar2 = (p) m.i(pVar);
                i = pVar2.d;
                cVar = pVar2.c;
                Unit unit = Unit.a;
            }
            Intrinsics.d(cVar);
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.g gVarBuilder = cVar.builder();
            gVarBuilder.subList(i2, i3).retainAll(collection);
            androidx.compose.runtime.external.kotlinx.collections.immutable.c cVarE = gVarBuilder.e();
            if (Intrinsics.b(cVarE, cVar)) {
                break;
            }
            p pVar3 = qVar.a;
            Intrinsics.e(pVar3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>");
            synchronized (m.b) {
                hVarK = m.k();
                zE = q.e((p) m.w(pVar3, qVar, hVarK), i, cVarE, true);
            }
            m.n(hVarK, qVar);
        } while (!zE);
        int size2 = size - qVar.size();
        if (size2 > 0) {
            this.c = this.a.i();
            this.d -= size2;
        }
        return size2 > 0;
    }

    @Override // java.util.List
    public final Object set(int i, Object obj) {
        r.a(i, this.d);
        a();
        int i2 = i + this.b;
        q qVar = this.a;
        Object obj2 = qVar.set(i2, obj);
        this.c = qVar.i();
        return obj2;
    }

    @Override // java.util.List, java.util.Collection
    public final int size() {
        return this.d;
    }

    @Override // java.util.List
    public final List subList(int i, int i2) {
        if (!(i >= 0 && i <= i2 && i2 <= this.d)) {
            AbstractC0805k0.a("fromIndex or toIndex are out of bounds");
        }
        a();
        int i3 = this.b;
        return new D(this.a, i + i3, i2 + i3);
    }

    @Override // java.util.List, java.util.Collection
    public final Object[] toArray() {
        return AbstractC4958q.a(this);
    }

    @Override // java.util.List
    public final ListIterator listIterator(int i) {
        a();
        H h = new H();
        h.a = i - 1;
        return new C(h, this);
    }

    @Override // java.util.List, java.util.Collection
    public final Object[] toArray(Object[] objArr) {
        return AbstractC4958q.b(this, objArr);
    }

    @Override // java.util.List
    public final boolean addAll(int i, Collection collection) {
        a();
        int i2 = i + this.b;
        q qVar = this.a;
        boolean zAddAll = qVar.addAll(i2, collection);
        if (zAddAll) {
            this.d = collection.size() + this.d;
            this.c = qVar.i();
        }
        return zAddAll;
    }

    @Override // java.util.List
    public final Object remove(int i) {
        a();
        int i2 = this.b + i;
        q qVar = this.a;
        Object objRemove = qVar.remove(i2);
        this.d--;
        this.c = qVar.i();
        return objRemove;
    }

    @Override // java.util.List
    public final void add(int i, Object obj) {
        a();
        int i2 = this.b + i;
        q qVar = this.a;
        qVar.add(i2, obj);
        this.d++;
        this.c = qVar.i();
    }
}
