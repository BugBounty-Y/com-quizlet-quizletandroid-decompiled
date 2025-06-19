package com.google.android.gms.internal.ads;

import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.ads.ou, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2459ou extends AbstractC2071fu implements Set {
    public static final /* synthetic */ int c = 0;
    public transient AbstractC2330lu b;

    public static int k(int i) {
        int iMax = Math.max(i, 2);
        if (iMax >= 751619276) {
            AbstractC1981ds.E("collection too large", iMax < 1073741824);
            return 1073741824;
        }
        int iHighestOneBit = Integer.highestOneBit(iMax - 1);
        do {
            iHighestOneBit += iHighestOneBit;
        } while (iHighestOneBit * 0.7d < iMax);
        return iHighestOneBit;
    }

    public static C2416nu n(int i) {
        C2416nu c2416nu = new C2416nu(i);
        c2416nu.e = new Object[k(i)];
        return c2416nu;
    }

    public static AbstractC2459ou o(int i, Object... objArr) {
        if (i == 0) {
            return Hu.j;
        }
        if (i == 1) {
            Object obj = objArr[0];
            Objects.requireNonNull(obj);
            return new Nu(obj);
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
            int iA = AbstractC2457os.a(iHashCode);
            while (true) {
                int i6 = iA & i2;
                Object obj3 = objArr2[i6];
                if (obj3 == null) {
                    objArr[i4] = obj2;
                    objArr2[i6] = obj2;
                    i3 += iHashCode;
                    i4++;
                    break;
                }
                if (!obj3.equals(obj2)) {
                    iA++;
                }
            }
        }
        Arrays.fill(objArr, i4, i, (Object) null);
        if (i4 == 1) {
            Object obj4 = objArr[0];
            Objects.requireNonNull(obj4);
            return new Nu(obj4);
        }
        if (k(i4) < iK / 2) {
            return o(i4, objArr);
        }
        int length = objArr.length;
        if (i4 < (length >> 1) + (length >> 2)) {
            objArr = Arrays.copyOf(objArr, i4);
        }
        return new Hu(objArr, i3, objArr2, i2, i4);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public AbstractC2330lu e() {
        AbstractC2330lu abstractC2330lu = this.b;
        if (abstractC2330lu != null) {
            return abstractC2330lu;
        }
        AbstractC2330lu abstractC2330luM = m();
        this.b = abstractC2330luM;
        return abstractC2330luM;
    }

    @Override // java.util.Collection, java.util.Set
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if ((obj instanceof AbstractC2459ou) && (this instanceof Hu)) {
            AbstractC2459ou abstractC2459ou = (AbstractC2459ou) obj;
            abstractC2459ou.getClass();
            if ((abstractC2459ou instanceof Hu) && hashCode() != obj.hashCode()) {
                return false;
            }
        }
        return AbstractC2543qs.x(this, obj);
    }

    @Override // java.util.Collection, java.util.Set
    public int hashCode() {
        return AbstractC2543qs.a(this);
    }

    public AbstractC2330lu m() {
        Object[] array = toArray(AbstractC2071fu.a);
        C2244ju c2244ju = AbstractC2330lu.b;
        return AbstractC2330lu.m(array.length, array);
    }
}
