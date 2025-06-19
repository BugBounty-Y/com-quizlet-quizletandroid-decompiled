package com.google.android.gms.internal.play_billing;

import java.util.Collections;
import java.util.Comparator;
import java.util.NavigableSet;
import java.util.SortedSet;

/* loaded from: classes2.dex */
public abstract class H extends G implements NavigableSet, InterfaceC3780a0 {
    public final transient Comparator c;
    public transient H d;

    public H(Comparator comparator) {
        this.c = comparator;
    }

    public final void addFirst(Object obj) {
        throw new UnsupportedOperationException();
    }

    public final void addLast(Object obj) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.SortedSet
    public final Comparator comparator() {
        return this.c;
    }

    @Override // java.util.NavigableSet
    public final NavigableSet descendingSet() {
        H y = this.d;
        if (y == null) {
            Y y2 = (Y) this;
            Comparator comparatorReverseOrder = Collections.reverseOrder(y2.c);
            if (!y2.isEmpty()) {
                y = new Y(y2.e.j(), comparatorReverseOrder);
            } else if (M.b.equals(comparatorReverseOrder)) {
                y = Y.f;
            } else {
                C3850y c3850y = B.b;
                y = new Y(Q.e, comparatorReverseOrder);
            }
            this.d = y;
            y.d = this;
        }
        return y;
    }

    @Override // java.util.SortedSet
    public abstract Object first();

    public final Object getFirst() {
        return first();
    }

    public final Object getLast() {
        return last();
    }

    @Override // java.util.NavigableSet, java.util.SortedSet
    public final SortedSet headSet(Object obj) {
        obj.getClass();
        Y y = (Y) this;
        return y.s(0, y.n(obj, false));
    }

    @Override // java.util.SortedSet
    public abstract Object last();

    @Override // java.util.NavigableSet
    public final Object pollFirst() {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.NavigableSet
    public final Object pollLast() {
        throw new UnsupportedOperationException();
    }

    public final Object removeFirst() {
        throw new UnsupportedOperationException();
    }

    public final Object removeLast() {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.NavigableSet
    public final NavigableSet subSet(Object obj, boolean z, Object obj2, boolean z2) {
        obj.getClass();
        obj2.getClass();
        if (this.c.compare(obj, obj2) > 0) {
            throw new IllegalArgumentException();
        }
        Y y = (Y) this;
        Y yS = y.s(y.o(obj, z), y.e.size());
        return yS.s(0, yS.n(obj2, z2));
    }

    @Override // java.util.NavigableSet, java.util.SortedSet
    public final SortedSet tailSet(Object obj) {
        obj.getClass();
        Y y = (Y) this;
        return y.s(y.o(obj, true), y.e.size());
    }

    @Override // java.util.NavigableSet
    public final NavigableSet headSet(Object obj, boolean z) {
        obj.getClass();
        Y y = (Y) this;
        return y.s(0, y.n(obj, z));
    }

    @Override // java.util.NavigableSet
    public final NavigableSet tailSet(Object obj, boolean z) {
        obj.getClass();
        Y y = (Y) this;
        return y.s(y.o(obj, z), y.e.size());
    }

    @Override // java.util.NavigableSet, java.util.SortedSet
    public final SortedSet subSet(Object obj, Object obj2) {
        obj.getClass();
        obj2.getClass();
        if (this.c.compare(obj, obj2) <= 0) {
            Y y = (Y) this;
            Y yS = y.s(y.o(obj, true), y.e.size());
            return yS.s(0, yS.n(obj2, false));
        }
        throw new IllegalArgumentException();
    }
}
