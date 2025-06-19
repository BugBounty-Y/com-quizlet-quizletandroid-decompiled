package com.google.android.gms.internal.ads;

import java.util.AbstractCollection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.RandomAccess;
import java.util.Set;

/* loaded from: classes2.dex */
public class Ku extends AbstractCollection implements Set {
    public final Set a;
    public final InterfaceC2715ut b;

    public Ku(Set set, InterfaceC2715ut interfaceC2715ut) {
        this.a = set;
        this.b = interfaceC2715ut;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean add(Object obj) {
        AbstractC1981ds.C(this.b.b(obj));
        return this.a.add(obj);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean addAll(Collection collection) {
        Iterator it2 = collection.iterator();
        while (it2.hasNext()) {
            AbstractC1981ds.C(this.b.b(it2.next()));
        }
        return this.a.addAll(collection);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final void clear() {
        Set set = this.a;
        boolean z = set instanceof RandomAccess;
        InterfaceC2715ut interfaceC2715ut = this.b;
        if (!z || !(set instanceof List)) {
            Iterator it2 = set.iterator();
            interfaceC2715ut.getClass();
            while (it2.hasNext()) {
                if (interfaceC2715ut.b(it2.next())) {
                    it2.remove();
                }
            }
            return;
        }
        List list = (List) set;
        interfaceC2715ut.getClass();
        int i = 0;
        for (int i2 = 0; i2 < list.size(); i2++) {
            Object obj = list.get(i2);
            if (!interfaceC2715ut.b(obj)) {
                if (i2 > i) {
                    try {
                        list.set(i, obj);
                    } catch (IllegalArgumentException unused) {
                        AbstractC2543qs.u(list, interfaceC2715ut, i, i2);
                        return;
                    } catch (UnsupportedOperationException unused2) {
                        AbstractC2543qs.u(list, interfaceC2715ut, i, i2);
                        return;
                    }
                }
                i++;
            }
        }
        list.subList(i, list.size()).clear();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        boolean zContains;
        Set set = this.a;
        set.getClass();
        try {
            zContains = set.contains(obj);
        } catch (ClassCastException | NullPointerException unused) {
            zContains = false;
        }
        if (zContains) {
            return this.b.b(obj);
        }
        return false;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean containsAll(Collection collection) {
        Iterator it2 = collection.iterator();
        while (it2.hasNext()) {
            if (!contains(it2.next())) {
                return false;
            }
        }
        return true;
    }

    @Override // java.util.Collection, java.util.Set
    public final boolean equals(Object obj) {
        return AbstractC2543qs.x(this, obj);
    }

    @Override // java.util.Collection, java.util.Set
    public final int hashCode() {
        return AbstractC2543qs.a(this);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean isEmpty() {
        Iterator it2 = this.a.iterator();
        InterfaceC2715ut interfaceC2715ut = this.b;
        AbstractC1981ds.x(interfaceC2715ut, "predicate");
        int i = 0;
        while (it2.hasNext()) {
            if (interfaceC2715ut.b(it2.next())) {
                return i == -1;
            }
            i++;
        }
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        Iterator it2 = this.a.iterator();
        it2.getClass();
        InterfaceC2715ut interfaceC2715ut = this.b;
        interfaceC2715ut.getClass();
        return new C2502pu(it2, interfaceC2715ut);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean remove(Object obj) {
        return contains(obj) && this.a.remove(obj);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean removeAll(Collection collection) {
        Iterator it2 = this.a.iterator();
        boolean z = false;
        while (it2.hasNext()) {
            Object next = it2.next();
            if (this.b.b(next) && collection.contains(next)) {
                it2.remove();
                z = true;
            }
        }
        return z;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean retainAll(Collection collection) {
        Iterator it2 = this.a.iterator();
        boolean z = false;
        while (it2.hasNext()) {
            Object next = it2.next();
            if (this.b.b(next) && !collection.contains(next)) {
                it2.remove();
                z = true;
            }
        }
        return z;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        Iterator it2 = this.a.iterator();
        int i = 0;
        while (it2.hasNext()) {
            if (this.b.b(it2.next())) {
                i++;
            }
        }
        return i;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final Object[] toArray() {
        Iterator it2 = iterator();
        ArrayList arrayList = new ArrayList();
        C2502pu c2502pu = (C2502pu) it2;
        while (c2502pu.hasNext()) {
            arrayList.add(c2502pu.next());
        }
        return arrayList.toArray();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final Object[] toArray(Object[] objArr) {
        Iterator it2 = iterator();
        ArrayList arrayList = new ArrayList();
        C2502pu c2502pu = (C2502pu) it2;
        while (c2502pu.hasNext()) {
            arrayList.add(c2502pu.next());
        }
        return arrayList.toArray(objArr);
    }
}
