package com.google.android.gms.internal.fido;

import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.fido.o, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2951o extends AbstractC2944h implements Set {
    public static final /* synthetic */ int c = 0;
    public transient AbstractC2949m b;

    public static AbstractC2951o h(int i, Object... objArr) {
        if (i == 0) {
            return C2960y.j;
        }
        if (i == 1) {
            Object obj = objArr[0];
            Objects.requireNonNull(obj);
            return new B(obj);
        }
        int iJ = j(i);
        Object[] objArr2 = new Object[iJ];
        int i2 = iJ - 1;
        int i3 = 0;
        int i4 = 0;
        for (int i5 = 0; i5 < i; i5++) {
            Object obj2 = objArr[i5];
            if (obj2 == null) {
                throw new NullPointerException(android.support.v4.media.session.a.f(i5, "at index "));
            }
            int iHashCode = obj2.hashCode();
            int iRotateLeft = (int) (Integer.rotateLeft((int) (iHashCode * (-862048943)), 15) * 461845907);
            while (true) {
                int i6 = iRotateLeft & i2;
                Object obj3 = objArr2[i6];
                if (obj3 == null) {
                    objArr[i4] = obj2;
                    objArr2[i6] = obj2;
                    i3 += iHashCode;
                    i4++;
                    break;
                }
                if (!obj3.equals(obj2)) {
                    iRotateLeft++;
                }
            }
        }
        Arrays.fill(objArr, i4, i, (Object) null);
        if (i4 == 1) {
            Object obj4 = objArr[0];
            Objects.requireNonNull(obj4);
            return new B(obj4);
        }
        if (j(i4) < iJ / 2) {
            return h(i4, objArr);
        }
        if (i4 <= 0) {
            objArr = Arrays.copyOf(objArr, i4);
        }
        return new C2960y(objArr, i3, objArr2, i2, i4);
    }

    public static int j(int i) {
        int iMax = Math.max(i, 2);
        if (iMax >= 751619276) {
            if (iMax < 1073741824) {
                return 1073741824;
            }
            throw new IllegalArgumentException("collection too large");
        }
        int iHighestOneBit = Integer.highestOneBit(iMax - 1);
        do {
            iHighestOneBit += iHighestOneBit;
        } while (iHighestOneBit * 0.7d < iMax);
        return iHighestOneBit;
    }

    @Override // java.util.Collection, java.util.Set
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if ((obj instanceof AbstractC2951o) && (this instanceof C2960y)) {
            AbstractC2951o abstractC2951o = (AbstractC2951o) obj;
            abstractC2951o.getClass();
            if (abstractC2951o instanceof C2960y) {
                if (((C2960y) this).e != obj.hashCode()) {
                    return false;
                }
            }
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Set)) {
            return false;
        }
        Set set = (Set) obj;
        try {
            if (size() == set.size()) {
                return containsAll(set);
            }
            return false;
        } catch (ClassCastException | NullPointerException unused) {
            return false;
        }
    }

    @Override // java.util.Collection, java.util.Set
    public int hashCode() {
        return AbstractC2937a.b(this);
    }

    public AbstractC2949m k() {
        AbstractC2949m abstractC2949m = this.b;
        if (abstractC2949m != null) {
            return abstractC2949m;
        }
        AbstractC2949m abstractC2949mM = m();
        this.b = abstractC2949mM;
        return abstractC2949mM;
    }

    public AbstractC2949m m() {
        Object[] array = toArray(AbstractC2944h.a);
        C2945i c2945i = AbstractC2949m.b;
        return AbstractC2949m.k(array.length, array);
    }
}
