package com.google.android.gms.internal.play_billing;

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Set;

/* loaded from: classes2.dex */
public final class Y extends H {
    public static final Y f;
    public final transient B e;

    static {
        C3850y c3850y = B.b;
        f = new Y(Q.e, M.b);
    }

    public Y(B b, Comparator comparator) {
        super(comparator);
        this.e = b;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final int a(Object[] objArr) {
        return this.e.a(objArr);
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final int b() {
        return this.e.b();
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final int c() {
        return this.e.c();
    }

    @Override // java.util.NavigableSet
    public final Object ceiling(Object obj) {
        int iO = o(obj, true);
        B b = this.e;
        if (iO == b.size()) {
            return null;
        }
        return b.get(iO);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        if (obj != null) {
            try {
                if (Collections.binarySearch(this.e, obj, this.c) >= 0) {
                    return true;
                }
            } catch (ClassCastException unused) {
            }
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean containsAll(Collection collection) {
        if (collection instanceof L) {
            collection = ((L) collection).zza();
        }
        Comparator comparator = this.c;
        if (!Z0.k(comparator, collection) || collection.size() <= 1) {
            return super.containsAll(collection);
        }
        C3850y c3850yListIterator = this.e.listIterator(0);
        Iterator it2 = collection.iterator();
        if (c3850yListIterator.hasNext()) {
            Object next = it2.next();
            Object next2 = c3850yListIterator.next();
            while (true) {
                try {
                    int iCompare = comparator.compare(next2, next);
                    if (iCompare >= 0) {
                        if (iCompare != 0) {
                            break;
                        }
                        if (!it2.hasNext()) {
                            return true;
                        }
                        next = it2.next();
                    } else {
                        if (!c3850yListIterator.hasNext()) {
                            break;
                        }
                        next2 = c3850yListIterator.next();
                    }
                } catch (ClassCastException | NullPointerException unused) {
                }
            }
        }
        return false;
    }

    @Override // java.util.NavigableSet
    public final Iterator descendingIterator() {
        return this.e.j().listIterator(0);
    }

    @Override // com.google.android.gms.internal.play_billing.G, com.google.android.gms.internal.play_billing.AbstractC3844w
    public final B e() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.play_billing.G, java.util.Collection, java.util.Set
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof Set) {
            Set set = (Set) obj;
            B b = this.e;
            if (b.size() == set.size()) {
                if (isEmpty()) {
                    return true;
                }
                Comparator comparator = this.c;
                if (!Z0.k(comparator, set)) {
                    return containsAll(set);
                }
                Iterator it2 = set.iterator();
                try {
                    C3850y c3850yListIterator = b.listIterator(0);
                    while (c3850yListIterator.hasNext()) {
                        Object next = c3850yListIterator.next();
                        Object next2 = it2.next();
                        if (next2 == null || comparator.compare(next, next2) != 0) {
                        }
                    }
                    return true;
                } catch (ClassCastException | NoSuchElementException unused) {
                }
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.play_billing.H, java.util.SortedSet
    public final Object first() {
        if (isEmpty()) {
            throw new NoSuchElementException();
        }
        return this.e.get(0);
    }

    @Override // java.util.NavigableSet
    public final Object floor(Object obj) {
        int iN = n(obj, true) - 1;
        if (iN == -1) {
            return null;
        }
        return this.e.get(iN);
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final Object[] h() {
        return this.e.h();
    }

    @Override // java.util.NavigableSet
    public final Object higher(Object obj) {
        int iO = o(obj, false);
        B b = this.e;
        if (iO == b.size()) {
            return null;
        }
        return b.get(iO);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set, java.util.NavigableSet
    public final /* synthetic */ Iterator iterator() {
        return this.e.listIterator(0);
    }

    @Override // com.google.android.gms.internal.play_billing.H, java.util.SortedSet
    public final Object last() {
        if (isEmpty()) {
            throw new NoSuchElementException();
        }
        return this.e.get(r0.size() - 1);
    }

    @Override // java.util.NavigableSet
    public final Object lower(Object obj) {
        int iN = n(obj, false) - 1;
        if (iN == -1) {
            return null;
        }
        return this.e.get(iN);
    }

    public final int n(Object obj, boolean z) {
        obj.getClass();
        int iBinarySearch = Collections.binarySearch(this.e, obj, this.c);
        return iBinarySearch >= 0 ? z ? iBinarySearch + 1 : iBinarySearch : ~iBinarySearch;
    }

    public final int o(Object obj, boolean z) {
        obj.getClass();
        int iBinarySearch = Collections.binarySearch(this.e, obj, this.c);
        return iBinarySearch >= 0 ? z ? iBinarySearch : iBinarySearch + 1 : ~iBinarySearch;
    }

    public final Y s(int i, int i2) {
        B b = this.e;
        if (i == 0) {
            if (i2 == b.size()) {
                return this;
            }
            i = 0;
        }
        Comparator comparator = this.c;
        if (i < i2) {
            return new Y(b.subList(i, i2), comparator);
        }
        if (M.b.equals(comparator)) {
            return f;
        }
        C3850y c3850y = B.b;
        return new Y(Q.e, comparator);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.e.size();
    }
}
