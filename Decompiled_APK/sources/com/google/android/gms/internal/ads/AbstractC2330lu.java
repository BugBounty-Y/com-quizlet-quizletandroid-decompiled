package com.google.android.gms.internal.ads;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.RandomAccess;

/* renamed from: com.google.android.gms.internal.ads.lu, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2330lu extends AbstractC2071fu implements List, RandomAccess {
    public static final C2244ju b = new C2244ju(Bu.e, 0);

    public static Bu m(int i, Object[] objArr) {
        return i == 0 ? Bu.e : new Bu(objArr, i);
    }

    public static AbstractC2330lu n(Collection collection) {
        if (!(collection instanceof AbstractC2071fu)) {
            Object[] array = collection.toArray();
            int length = array.length;
            AbstractC2457os.q(length, array);
            return m(length, array);
        }
        AbstractC2330lu abstractC2330luE = ((AbstractC2071fu) collection).e();
        if (!abstractC2330luE.h()) {
            return abstractC2330luE;
        }
        Object[] array2 = abstractC2330luE.toArray(AbstractC2071fu.a);
        return m(array2.length, array2);
    }

    public static Bu o(Object[] objArr) {
        if (objArr.length == 0) {
            return Bu.e;
        }
        Object[] objArr2 = (Object[]) objArr.clone();
        int length = objArr2.length;
        AbstractC2457os.q(length, objArr2);
        return m(length, objArr2);
    }

    public static Bu s(Object obj) {
        Object[] objArr = {obj};
        AbstractC2457os.q(1, objArr);
        return m(1, objArr);
    }

    public static Bu t(Object obj, Object obj2) {
        Object[] objArr = {obj, obj2};
        AbstractC2457os.q(2, objArr);
        return m(2, objArr);
    }

    public static Bu u(Long l, Long l2, Long l3, Long l4, Long l5) {
        Object[] objArr = {l, l2, l3, l4, l5};
        AbstractC2457os.q(5, objArr);
        return m(5, objArr);
    }

    public static Bu v(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, Object obj6, Object obj7, Object obj8, Object obj9, Object obj10, Object obj11, Object obj12, Object... objArr) {
        int length = objArr.length;
        int i = length + 12;
        Object[] objArr2 = new Object[i];
        objArr2[0] = obj;
        objArr2[1] = obj2;
        objArr2[2] = obj3;
        objArr2[3] = obj4;
        objArr2[4] = obj5;
        objArr2[5] = obj6;
        objArr2[6] = obj7;
        objArr2[7] = obj8;
        objArr2[8] = obj9;
        objArr2[9] = obj10;
        objArr2[10] = obj11;
        objArr2[11] = obj12;
        System.arraycopy(objArr, 0, objArr2, 12, length);
        AbstractC2457os.q(i, objArr2);
        return m(i, objArr2);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
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

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        return indexOf(obj) >= 0;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final AbstractC2330lu e() {
        return this;
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
                        if (AbstractC2457os.l(get(i), list.get(i))) {
                        }
                    }
                    return true;
                }
                C2244ju c2244juListIterator = listIterator(0);
                Iterator it2 = list.iterator();
                while (true) {
                    if (c2244juListIterator.hasNext()) {
                        if (!it2.hasNext() || !AbstractC2457os.l(c2244juListIterator.next(), it2.next())) {
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

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final Pu g() {
        return listIterator(0);
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
    /* renamed from: k, reason: merged with bridge method [inline-methods] */
    public AbstractC2330lu subList(int i, int i2) {
        AbstractC1981ds.K(i, i2, size());
        int i3 = i2 - i;
        return i3 == size() ? this : i3 == 0 ? Bu.e : new C2287ku(this, i, i3);
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

    @Override // java.util.List
    /* renamed from: w, reason: merged with bridge method [inline-methods] */
    public final C2244ju listIterator(int i) {
        AbstractC1981ds.p(i, size());
        return isEmpty() ? b : new C2244ju(this, i);
    }
}
