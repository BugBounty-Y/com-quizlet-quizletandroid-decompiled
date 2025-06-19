package com.google.common.collect;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3531s4;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.RandomAccess;

/* loaded from: classes2.dex */
public abstract class j extends AbstractC3923f implements List, RandomAccess {
    public static final C3922e b = new C3922e(x.e, 0);

    public static x k(int i, Object[] objArr) {
        return i == 0 ? x.e : new x(objArr, i);
    }

    public static j m(Collection collection) {
        if (!(collection instanceof AbstractC3923f)) {
            Object[] array = collection.toArray();
            AbstractC3531s4.e(array.length, array);
            return k(array.length, array);
        }
        j jVarA = ((AbstractC3923f) collection).a();
        if (!jVarA.h()) {
            return jVarA;
        }
        Object[] array2 = jVarA.toArray(AbstractC3923f.a);
        return k(array2.length, array2);
    }

    private void readObject(ObjectInputStream objectInputStream) throws InvalidObjectException {
        throw new InvalidObjectException("Use SerializedForm");
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final j a() {
        return this;
    }

    @Override // java.util.List
    public final void add(int i, Object obj) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.List
    public final boolean addAll(int i, Collection collection) {
        throw new UnsupportedOperationException();
    }

    @Override // com.google.common.collect.AbstractC3923f
    public int b(Object[] objArr) {
        int size = size();
        for (int i = 0; i < size; i++) {
            objArr[i] = get(i);
        }
        return size;
    }

    @Override // com.google.common.collect.AbstractC3923f, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean contains(Object obj) {
        return indexOf(obj) >= 0;
    }

    @Override // java.util.Collection, java.util.List
    public final boolean equals(Object obj) {
        if (obj != this) {
            if (obj instanceof List) {
                List list = (List) obj;
                int size = size();
                if (size == list.size()) {
                    if (!(list instanceof RandomAccess)) {
                        Iterator it2 = list.iterator();
                        for (Object obj2 : this) {
                            if (it2.hasNext()) {
                                Object next = it2.next();
                                if (obj2 != next && (obj2 == null || !obj2.equals(next))) {
                                    return false;
                                }
                            }
                        }
                        return !it2.hasNext();
                    }
                    for (int i = 0; i < size; i++) {
                        Object obj3 = get(i);
                        Object obj4 = list.get(i);
                        if (obj3 != obj4 && (obj3 == null || !obj3.equals(obj4))) {
                            return false;
                        }
                    }
                }
            }
            return false;
        }
        return true;
    }

    @Override // java.util.Collection, java.util.List
    public final int hashCode() {
        int size = size();
        int i = 1;
        for (int i2 = 0; i2 < size; i2++) {
            i = ~(~(get(i2).hashCode() + (i * 31)));
        }
        return i;
    }

    public int indexOf(Object obj) {
        if (obj == null) {
            return -1;
        }
        int size = size();
        for (int i = 0; i < size; i++) {
            if (obj.equals(get(i))) {
                return i;
            }
        }
        return -1;
    }

    @Override // com.google.common.collect.AbstractC3923f, java.util.AbstractCollection, java.util.Collection, java.lang.Iterable
    public Iterator iterator() {
        return listIterator(0);
    }

    @Override // com.google.common.collect.AbstractC3923f
    /* renamed from: j */
    public final com.google.android.gms.internal.common.g iterator() {
        return listIterator(0);
    }

    public int lastIndexOf(Object obj) {
        if (obj == null) {
            return -1;
        }
        for (int size = size() - 1; size >= 0; size--) {
            if (obj.equals(get(size))) {
                return size;
            }
        }
        return -1;
    }

    @Override // java.util.List
    /* renamed from: n, reason: merged with bridge method [inline-methods] */
    public final C3922e listIterator(int i) {
        com.google.common.base.b.d(i, size());
        return isEmpty() ? b : new C3922e(this, i);
    }

    public j o() {
        return size() <= 1 ? this : new g(this);
    }

    @Override // java.util.List
    public final Object remove(int i) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.List
    /* renamed from: s, reason: merged with bridge method [inline-methods] */
    public j subList(int i, int i2) {
        com.google.common.base.b.e(i, i2, size());
        int i3 = i2 - i;
        return i3 == size() ? this : i3 == 0 ? x.e : new i(this, i, i3);
    }

    @Override // java.util.List
    public final Object set(int i, Object obj) {
        throw new UnsupportedOperationException();
    }

    @Override // com.google.common.collect.AbstractC3923f
    public Object writeReplace() {
        return new h(toArray(AbstractC3923f.a));
    }

    public ListIterator listIterator() {
        return listIterator(0);
    }
}
