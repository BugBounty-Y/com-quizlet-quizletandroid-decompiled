package com.google.common.collect;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3520q4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3525r4;
import com.google.common.base.Predicate;
import java.util.AbstractCollection;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.RandomAccess;

/* renamed from: com.google.common.collect.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3920c extends AbstractCollection {
    public final Collection a;
    public final Predicate b;

    public C3920c(Collection collection, Predicate predicate) {
        this.a = collection;
        this.b = predicate;
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean add(Object obj) {
        com.google.common.base.b.b(this.b.apply(obj));
        return this.a.add(obj);
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean addAll(Collection collection) {
        Iterator it2 = collection.iterator();
        while (it2.hasNext()) {
            com.google.common.base.b.b(this.b.apply(it2.next()));
        }
        return this.a.addAll(collection);
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final void clear() {
        Collection collection = this.a;
        boolean z = collection instanceof RandomAccess;
        Predicate predicate = this.b;
        if (!z || !(collection instanceof List)) {
            Iterator it2 = collection.iterator();
            predicate.getClass();
            while (it2.hasNext()) {
                if (predicate.apply(it2.next())) {
                    it2.remove();
                }
            }
            return;
        }
        List list = (List) collection;
        predicate.getClass();
        int i = 0;
        for (int i2 = 0; i2 < list.size(); i2++) {
            Object obj = list.get(i2);
            if (!predicate.apply(obj)) {
                if (i2 > i) {
                    try {
                        list.set(i, obj);
                    } catch (IllegalArgumentException unused) {
                        AbstractC3520q4.a(list, predicate, i, i2);
                        return;
                    } catch (UnsupportedOperationException unused2) {
                        AbstractC3520q4.a(list, predicate, i, i2);
                        return;
                    }
                }
                i++;
            }
        }
        list.subList(i, list.size()).clear();
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean contains(Object obj) {
        boolean zContains;
        Collection collection = this.a;
        collection.getClass();
        try {
            zContains = collection.contains(obj);
        } catch (ClassCastException | NullPointerException unused) {
            zContains = false;
        }
        if (zContains) {
            return this.b.apply(obj);
        }
        return false;
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean containsAll(Collection collection) {
        Iterator it2 = collection.iterator();
        while (it2.hasNext()) {
            if (!contains(it2.next())) {
                return false;
            }
        }
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean isEmpty() {
        Iterator it2 = this.a.iterator();
        Predicate predicate = this.b;
        if (predicate == null) {
            throw new NullPointerException("predicate");
        }
        int i = 0;
        while (true) {
            if (!it2.hasNext()) {
                i = -1;
                break;
            }
            if (predicate.apply(it2.next())) {
                break;
            }
            i++;
        }
        return true ^ (i != -1);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        Iterator it2 = this.a.iterator();
        it2.getClass();
        Predicate predicate = this.b;
        predicate.getClass();
        return new p(it2, predicate);
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean remove(Object obj) {
        return contains(obj) && this.a.remove(obj);
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean removeAll(Collection collection) {
        Iterator it2 = this.a.iterator();
        boolean z = false;
        while (it2.hasNext()) {
            Object next = it2.next();
            if (this.b.apply(next) && collection.contains(next)) {
                it2.remove();
                z = true;
            }
        }
        return z;
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean retainAll(Collection collection) {
        Iterator it2 = this.a.iterator();
        boolean z = false;
        while (it2.hasNext()) {
            Object next = it2.next();
            if (this.b.apply(next) && !collection.contains(next)) {
                it2.remove();
                z = true;
            }
        }
        return z;
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final int size() {
        Iterator it2 = this.a.iterator();
        int i = 0;
        while (it2.hasNext()) {
            if (this.b.apply(it2.next())) {
                i++;
            }
        }
        return i;
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final Object[] toArray() {
        return AbstractC3525r4.d(iterator()).toArray();
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final Object[] toArray(Object[] objArr) {
        return AbstractC3525r4.d(iterator()).toArray(objArr);
    }
}
