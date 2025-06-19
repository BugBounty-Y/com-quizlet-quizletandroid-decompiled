package com.google.android.gms.internal.fido;

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.fido.z, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2961z extends AbstractC2954s {
    public static final C2961z g;
    public final transient AbstractC2949m f;

    static {
        C2945i c2945i = AbstractC2949m.b;
        g = new C2961z(C2959x.e, C2957v.b);
    }

    public C2961z(AbstractC2949m abstractC2949m, Comparator comparator) {
        super(comparator);
        this.f = abstractC2949m;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final int a(Object[] objArr) {
        return this.f.a(objArr);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final int b() {
        return this.f.b();
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final int c() {
        return this.f.c();
    }

    @Override // java.util.NavigableSet
    public final Object ceiling(Object obj) {
        int iU = u(obj, true);
        AbstractC2949m abstractC2949m = this.f;
        if (iU == abstractC2949m.size()) {
            return null;
        }
        return abstractC2949m.get(iU);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        if (obj != null) {
            try {
                if (Collections.binarySearch(this.f, obj, this.d) >= 0) {
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
        if (collection instanceof InterfaceC2956u) {
            collection = ((InterfaceC2956u) collection).zza();
        }
        Comparator comparator = this.d;
        if (!AbstractC2937a.j(comparator, collection) || collection.size() <= 1) {
            return super.containsAll(collection);
        }
        C2945i c2945iListIterator = this.f.listIterator(0);
        Iterator it2 = collection.iterator();
        if (c2945iListIterator.hasNext()) {
            Object next = it2.next();
            Object next2 = c2945iListIterator.next();
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
                        if (!c2945iListIterator.hasNext()) {
                            break;
                        }
                        next2 = c2945iListIterator.next();
                    }
                } catch (ClassCastException | NullPointerException unused) {
                }
            }
        }
        return false;
    }

    @Override // java.util.NavigableSet
    public final Iterator descendingIterator() {
        return this.f.h().listIterator(0);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final D e() {
        return this.f.listIterator(0);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2951o, java.util.Collection, java.util.Set
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof Set) {
            Set set = (Set) obj;
            AbstractC2949m abstractC2949m = this.f;
            if (abstractC2949m.size() == set.size()) {
                if (isEmpty()) {
                    return true;
                }
                Comparator comparator = this.d;
                if (!AbstractC2937a.j(comparator, set)) {
                    return containsAll(set);
                }
                Iterator it2 = set.iterator();
                try {
                    C2945i c2945iListIterator = abstractC2949m.listIterator(0);
                    while (c2945iListIterator.hasNext()) {
                        Object next = c2945iListIterator.next();
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

    @Override // com.google.android.gms.internal.fido.AbstractC2954s, java.util.SortedSet
    public final Object first() {
        if (isEmpty()) {
            throw new NoSuchElementException();
        }
        return this.f.get(0);
    }

    @Override // java.util.NavigableSet
    public final Object floor(Object obj) {
        int iT = t(obj, true) - 1;
        if (iT == -1) {
            return null;
        }
        return this.f.get(iT);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final Object[] g() {
        return this.f.g();
    }

    @Override // java.util.NavigableSet
    public final Object higher(Object obj) {
        int iU = u(obj, false);
        AbstractC2949m abstractC2949m = this.f;
        if (iU == abstractC2949m.size()) {
            return null;
        }
        return abstractC2949m.get(iU);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set, java.util.NavigableSet
    public final /* synthetic */ Iterator iterator() {
        return this.f.listIterator(0);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2951o
    public final AbstractC2949m k() {
        return this.f;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2954s, java.util.SortedSet
    public final Object last() {
        if (isEmpty()) {
            throw new NoSuchElementException();
        }
        return this.f.get(r0.size() - 1);
    }

    @Override // java.util.NavigableSet
    public final Object lower(Object obj) {
        int iT = t(obj, false) - 1;
        if (iT == -1) {
            return null;
        }
        return this.f.get(iT);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.f.size();
    }

    public final int t(Object obj, boolean z) {
        obj.getClass();
        int iBinarySearch = Collections.binarySearch(this.f, obj, this.d);
        return iBinarySearch >= 0 ? z ? iBinarySearch + 1 : iBinarySearch : ~iBinarySearch;
    }

    public final int u(Object obj, boolean z) {
        obj.getClass();
        int iBinarySearch = Collections.binarySearch(this.f, obj, this.d);
        return iBinarySearch >= 0 ? z ? iBinarySearch : iBinarySearch + 1 : ~iBinarySearch;
    }

    public final C2961z v(int i, int i2) {
        AbstractC2949m abstractC2949m = this.f;
        if (i == 0) {
            if (i2 == abstractC2949m.size()) {
                return this;
            }
            i = 0;
        }
        Comparator comparator = this.d;
        return i < i2 ? new C2961z(abstractC2949m.subList(i, i2), comparator) : AbstractC2954s.s(comparator);
    }
}
