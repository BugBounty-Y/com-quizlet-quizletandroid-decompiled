package com.google.common.collect;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3514p4;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;

/* loaded from: classes2.dex */
public abstract class o extends AbstractC3923f implements Set {
    public static final /* synthetic */ int c = 0;
    public transient j b;

    public static int k(int i) {
        int iMax = Math.max(i, 2);
        if (iMax >= 751619276) {
            if (iMax < 1073741824) {
                return 1073741824;
            }
            throw new IllegalArgumentException("collection too large");
        }
        int iHighestOneBit = Integer.highestOneBit(iMax - 1) << 1;
        while (iHighestOneBit * 0.7d < iMax) {
            iHighestOneBit <<= 1;
        }
        return iHighestOneBit;
    }

    public static o m(int i, Object... objArr) {
        if (i == 0) {
            return D.j;
        }
        if (i == 1) {
            Object obj = objArr[0];
            Objects.requireNonNull(obj);
            return new E(obj);
        }
        int iK = k(i);
        Object[] objArr2 = new Object[iK];
        int i2 = iK - 1;
        int i3 = 0;
        int i4 = 0;
        for (int i5 = 0; i5 < i; i5++) {
            Object obj2 = objArr[i5];
            if (obj2 == null) {
                throw new NullPointerException(android.support.v4.media.session.a.f(i5, "at index "));
            }
            int iHashCode = obj2.hashCode();
            int iB = AbstractC3514p4.b(iHashCode);
            while (true) {
                int i6 = iB & i2;
                Object obj3 = objArr2[i6];
                if (obj3 == null) {
                    objArr[i4] = obj2;
                    objArr2[i6] = obj2;
                    i3 += iHashCode;
                    i4++;
                    break;
                }
                if (obj3.equals(obj2)) {
                    break;
                }
                iB++;
            }
        }
        Arrays.fill(objArr, i4, i, (Object) null);
        if (i4 == 1) {
            Object obj4 = objArr[0];
            Objects.requireNonNull(obj4);
            return new E(obj4);
        }
        if (k(i4) < iK / 2) {
            return m(i4, objArr);
        }
        int length = objArr.length;
        if (i4 < (length >> 1) + (length >> 2)) {
            objArr = Arrays.copyOf(objArr, i4);
        }
        return new D(objArr, i3, objArr2, i2, i4);
    }

    public static o n(Set set) {
        if ((set instanceof o) && !(set instanceof SortedSet)) {
            o oVar = (o) set;
            if (!oVar.h()) {
                return oVar;
            }
        }
        Object[] array = set.toArray();
        return m(array.length, array);
    }

    private void readObject(ObjectInputStream objectInputStream) throws InvalidObjectException {
        throw new InvalidObjectException("Use SerializedForm");
    }

    @Override // com.google.common.collect.AbstractC3923f
    public j a() {
        j jVar = this.b;
        if (jVar != null) {
            return jVar;
        }
        j jVarO = o();
        this.b = jVarO;
        return jVarO;
    }

    @Override // java.util.Collection, java.util.Set
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if ((obj instanceof o) && (this instanceof D)) {
            o oVar = (o) obj;
            oVar.getClass();
            if ((oVar instanceof D) && hashCode() != obj.hashCode()) {
                return false;
            }
        }
        if (this != obj) {
            if (obj instanceof Set) {
                Set set = (Set) obj;
                try {
                    if (size() == set.size()) {
                        if (containsAll(set)) {
                        }
                    }
                } catch (ClassCastException | NullPointerException unused) {
                }
            }
            return false;
        }
        return true;
    }

    @Override // java.util.Collection, java.util.Set
    public int hashCode() {
        Iterator it2 = iterator();
        int i = 0;
        while (it2.hasNext()) {
            Object next = it2.next();
            i = ~(~(i + (next != null ? next.hashCode() : 0)));
        }
        return i;
    }

    public j o() {
        Object[] array = toArray(AbstractC3923f.a);
        C3922e c3922e = j.b;
        return j.k(array.length, array);
    }

    @Override // com.google.common.collect.AbstractC3923f
    public Object writeReplace() {
        return new n(toArray(AbstractC3923f.a));
    }
}
