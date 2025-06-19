package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.RandomAccess;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.x, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3292x extends AbstractC3252s implements List, RandomAccess {
    public static final C3276v b = new C3276v(B.e, 0);

    public static B h(Object obj, Object obj2) {
        Object[] objArr = {obj, obj2};
        for (int i = 0; i < 2; i++) {
            if (objArr[i] == null) {
                throw new NullPointerException(android.support.v4.media.session.a.f(i, "at index "));
            }
        }
        return new B(objArr, 2);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3252s
    public int a(Object[] objArr, int i) {
        int size = size();
        for (int i2 = 0; i2 < size; i2++) {
            objArr[i + i2] = get(i2);
        }
        return i + size;
    }

    @Override // java.util.List
    public final void add(int i, Object obj) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.List
    public final boolean addAll(int i, Collection collection) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        return indexOf(obj) >= 0;
    }

    @Override // java.util.Collection, java.util.List
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof List) {
            List list = (List) obj;
            int size = size();
            if (size == list.size()) {
                if (list instanceof RandomAccess) {
                    for (int i = 0; i < size; i++) {
                        if (com.google.android.gms.internal.mlkit_vision_common.H3.b(get(i), list.get(i))) {
                        }
                    }
                    return true;
                }
                C3276v c3276vListIterator = listIterator(0);
                Iterator it2 = list.iterator();
                while (true) {
                    if (c3276vListIterator.hasNext()) {
                        if (!it2.hasNext() || !com.google.android.gms.internal.mlkit_vision_common.H3.b(c3276vListIterator.next(), it2.next())) {
                            break;
                        }
                    } else if (!it2.hasNext()) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    @Override // java.util.List
    /* renamed from: g */
    public AbstractC3292x subList(int i, int i2) {
        com.google.android.gms.internal.mlkit_vision_common.I3.e(i, i2, size());
        int i3 = i2 - i;
        return i3 == size() ? this : i3 == 0 ? B.e : new C3284w(this, i, i3);
    }

    @Override // java.util.Collection, java.util.List
    public final int hashCode() {
        int size = size();
        int iHashCode = 1;
        for (int i = 0; i < size; i++) {
            iHashCode = (iHashCode * 31) + get(i).hashCode();
        }
        return iHashCode;
    }

    @Override // java.util.List
    public final int indexOf(Object obj) {
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

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.List
    public final /* synthetic */ Iterator iterator() {
        return listIterator(0);
    }

    @Override // java.util.List
    /* renamed from: j, reason: merged with bridge method [inline-methods] */
    public final C3276v listIterator(int i) {
        int size = size();
        if (i < 0 || i > size) {
            throw new IndexOutOfBoundsException(com.google.android.gms.internal.mlkit_vision_common.I3.f(i, size, "index"));
        }
        return isEmpty() ? b : new C3276v(this, i);
    }

    @Override // java.util.List
    public final int lastIndexOf(Object obj) {
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
    public final /* synthetic */ ListIterator listIterator() {
        return listIterator(0);
    }

    @Override // java.util.List
    public final Object remove(int i) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.List
    public final Object set(int i, Object obj) {
        throw new UnsupportedOperationException();
    }
}
