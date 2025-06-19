package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.internal.ads.Tt;
import java.io.Serializable;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/* loaded from: classes2.dex */
public final class r extends AbstractMap implements Serializable {
    public static final Object j = new Object();
    public transient Object a;
    public transient int[] b;
    public transient Object[] c;
    public transient Object[] d;
    public transient int e = Math.min(Math.max(12, 1), 1073741823);
    public transient int f;
    public transient C3226p g;
    public transient C3226p h;
    public transient Tt i;

    public final int[] a() {
        int[] iArr = this.b;
        Objects.requireNonNull(iArr);
        return iArr;
    }

    public final Object[] b() {
        Object[] objArr = this.c;
        Objects.requireNonNull(objArr);
        return objArr;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final void clear() {
        if (g()) {
            return;
        }
        this.e += 32;
        Map mapE = e();
        if (mapE != null) {
            this.e = Math.min(Math.max(size(), 3), 1073741823);
            mapE.clear();
            this.a = null;
            this.f = 0;
            return;
        }
        Arrays.fill(b(), 0, this.f, (Object) null);
        Arrays.fill(d(), 0, this.f, (Object) null);
        Object obj = this.a;
        Objects.requireNonNull(obj);
        if (obj instanceof byte[]) {
            Arrays.fill((byte[]) obj, (byte) 0);
        } else if (obj instanceof short[]) {
            Arrays.fill((short[]) obj, (short) 0);
        } else {
            Arrays.fill((int[]) obj, 0);
        }
        Arrays.fill(a(), 0, this.f, 0);
        this.f = 0;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean containsKey(Object obj) {
        Map mapE = e();
        return mapE != null ? mapE.containsKey(obj) : j(obj) != -1;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean containsValue(Object obj) {
        Map mapE = e();
        if (mapE != null) {
            return mapE.containsValue(obj);
        }
        for (int i = 0; i < this.f; i++) {
            if (com.google.android.gms.internal.mlkit_vision_common.H3.b(obj, d()[i])) {
                return true;
            }
        }
        return false;
    }

    public final Object[] d() {
        Object[] objArr = this.d;
        Objects.requireNonNull(objArr);
        return objArr;
    }

    public final Map e() {
        Object obj = this.a;
        if (obj instanceof Map) {
            return (Map) obj;
        }
        return null;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Set entrySet() {
        C3226p c3226p = this.h;
        if (c3226p != null) {
            return c3226p;
        }
        C3226p c3226p2 = new C3226p(this, 0);
        this.h = c3226p2;
        return c3226p2;
    }

    public final void f(int i, int i2) {
        Object obj = this.a;
        Objects.requireNonNull(obj);
        int[] iArrA = a();
        Object[] objArrB = b();
        Object[] objArrD = d();
        int size = size();
        int i3 = size - 1;
        if (i >= i3) {
            objArrB[i] = null;
            objArrD[i] = null;
            iArrA[i] = 0;
            return;
        }
        int i4 = i + 1;
        Object obj2 = objArrB[i3];
        objArrB[i] = obj2;
        objArrD[i] = objArrD[i3];
        objArrB[i3] = null;
        objArrD[i3] = null;
        iArrA[i] = iArrA[i3];
        iArrA[i3] = 0;
        int iB = com.google.android.gms.internal.mlkit_vision_common.L3.b(obj2) & i2;
        int iE = com.google.android.gms.internal.mlkit_vision_common.K3.e(iB, obj);
        if (iE == size) {
            com.google.android.gms.internal.mlkit_vision_common.K3.g(iB, i4, obj);
            return;
        }
        while (true) {
            int i5 = iE - 1;
            int i6 = iArrA[i5];
            int i7 = i6 & i2;
            if (i7 == size) {
                iArrA[i5] = (i6 & (~i2)) | (i2 & i4);
                return;
            }
            iE = i7;
        }
    }

    public final boolean g() {
        return this.a == null;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object get(Object obj) {
        Map mapE = e();
        if (mapE != null) {
            return mapE.get(obj);
        }
        int iJ = j(obj);
        if (iJ == -1) {
            return null;
        }
        return d()[iJ];
    }

    public final int h() {
        return (1 << (this.e & 31)) - 1;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean isEmpty() {
        return size() == 0;
    }

    public final int j(Object obj) {
        if (g()) {
            return -1;
        }
        int iB = com.google.android.gms.internal.mlkit_vision_common.L3.b(obj);
        int iH = h();
        Object obj2 = this.a;
        Objects.requireNonNull(obj2);
        int iE = com.google.android.gms.internal.mlkit_vision_common.K3.e(iB & iH, obj2);
        if (iE != 0) {
            int i = ~iH;
            int i2 = iB & i;
            do {
                int i3 = iE - 1;
                int i4 = a()[i3];
                if ((i4 & i) == i2 && com.google.android.gms.internal.mlkit_vision_common.H3.b(obj, b()[i3])) {
                    return i3;
                }
                iE = i4 & iH;
            } while (iE != 0);
        }
        return -1;
    }

    public final int k(int i, int i2, int i3, int i4) {
        int i5 = i2 - 1;
        Object objF = com.google.android.gms.internal.mlkit_vision_common.K3.f(i2);
        if (i4 != 0) {
            com.google.android.gms.internal.mlkit_vision_common.K3.g(i3 & i5, i4 + 1, objF);
        }
        Object obj = this.a;
        Objects.requireNonNull(obj);
        int[] iArrA = a();
        for (int i6 = 0; i6 <= i; i6++) {
            int iE = com.google.android.gms.internal.mlkit_vision_common.K3.e(i6, obj);
            while (iE != 0) {
                int i7 = iE - 1;
                int i8 = iArrA[i7];
                int i9 = ((~i) & i8) | i6;
                int i10 = i9 & i5;
                int iE2 = com.google.android.gms.internal.mlkit_vision_common.K3.e(i10, objF);
                com.google.android.gms.internal.mlkit_vision_common.K3.g(i10, iE, objF);
                iArrA[i7] = ((~i5) & i9) | (iE2 & i5);
                iE = i8 & i;
            }
        }
        this.a = objF;
        this.e = ((32 - Integer.numberOfLeadingZeros(i5)) & 31) | (this.e & (-32));
        return i5;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Set keySet() {
        C3226p c3226p = this.g;
        if (c3226p != null) {
            return c3226p;
        }
        C3226p c3226p2 = new C3226p(this, 1);
        this.g = c3226p2;
        return c3226p2;
    }

    public final Object l(Object obj) {
        if (!g()) {
            int iH = h();
            Object obj2 = this.a;
            Objects.requireNonNull(obj2);
            int iD = com.google.android.gms.internal.mlkit_vision_common.K3.d(obj, null, iH, obj2, a(), b(), null);
            if (iD != -1) {
                Object obj3 = d()[iD];
                f(iD, iH);
                this.f--;
                this.e += 32;
                return obj3;
            }
        }
        return j;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object put(Object obj, Object obj2) {
        int i;
        int i2 = 32;
        if (g()) {
            if (!g()) {
                throw new IllegalStateException("Arrays already allocated");
            }
            int i3 = this.e;
            int iMax = Math.max(i3 + 1, 2);
            int iHighestOneBit = Integer.highestOneBit(iMax);
            if (iMax > iHighestOneBit && (iHighestOneBit = iHighestOneBit + iHighestOneBit) <= 0) {
                iHighestOneBit = 1073741824;
            }
            int iMax2 = Math.max(4, iHighestOneBit);
            this.a = com.google.android.gms.internal.mlkit_vision_common.K3.f(iMax2);
            this.e = ((32 - Integer.numberOfLeadingZeros(iMax2 - 1)) & 31) | (this.e & (-32));
            this.b = new int[i3];
            this.c = new Object[i3];
            this.d = new Object[i3];
        }
        Map mapE = e();
        if (mapE != null) {
            return mapE.put(obj, obj2);
        }
        int[] iArrA = a();
        Object[] objArrB = b();
        Object[] objArrD = d();
        int i4 = this.f;
        int i5 = i4 + 1;
        int iB = com.google.android.gms.internal.mlkit_vision_common.L3.b(obj);
        int iH = h();
        int i6 = iB & iH;
        Object obj3 = this.a;
        Objects.requireNonNull(obj3);
        int iE = com.google.android.gms.internal.mlkit_vision_common.K3.e(i6, obj3);
        if (iE == 0) {
            if (i5 > iH) {
                iH = k(iH, (iH + 1) * (iH < 32 ? 4 : 2), iB, i4);
            } else {
                Object obj4 = this.a;
                Objects.requireNonNull(obj4);
                com.google.android.gms.internal.mlkit_vision_common.K3.g(i6, i5, obj4);
            }
            i = 1;
        } else {
            int i7 = ~iH;
            int i8 = iB & i7;
            int i9 = 0;
            while (true) {
                int i10 = iE - 1;
                int i11 = iArrA[i10];
                i = 1;
                int i12 = i11 & i7;
                int i13 = i2;
                if (i12 == i8 && com.google.android.gms.internal.mlkit_vision_common.H3.b(obj, objArrB[i10])) {
                    Object obj5 = objArrD[i10];
                    objArrD[i10] = obj2;
                    return obj5;
                }
                int i14 = i11 & iH;
                int i15 = i9 + 1;
                if (i14 != 0) {
                    i9 = i15;
                    iE = i14;
                    i2 = i13;
                } else {
                    if (i15 >= 9) {
                        LinkedHashMap linkedHashMap = new LinkedHashMap(h() + 1, 1.0f);
                        int i16 = isEmpty() ? -1 : 0;
                        while (i16 >= 0) {
                            linkedHashMap.put(b()[i16], d()[i16]);
                            int i17 = i16 + 1;
                            i16 = i17 < this.f ? i17 : -1;
                        }
                        this.a = linkedHashMap;
                        this.b = null;
                        this.c = null;
                        this.d = null;
                        this.e += 32;
                        return linkedHashMap.put(obj, obj2);
                    }
                    if (i5 > iH) {
                        iH = k(iH, (iH + 1) * (iH < i13 ? 4 : 2), iB, i4);
                    } else {
                        iArrA[i10] = i12 | (i5 & iH);
                    }
                }
            }
        }
        int length = a().length;
        if (i5 > length) {
            int i18 = i;
            int iMin = Math.min(1073741823, (Math.max(i18, length >>> 1) + length) | i18);
            if (iMin != length) {
                this.b = Arrays.copyOf(a(), iMin);
                this.c = Arrays.copyOf(b(), iMin);
                this.d = Arrays.copyOf(d(), iMin);
            }
        }
        a()[i4] = (~iH) & iB;
        b()[i4] = obj;
        d()[i4] = obj2;
        this.f = i5;
        this.e += 32;
        return null;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object remove(Object obj) {
        Map mapE = e();
        if (mapE != null) {
            return mapE.remove(obj);
        }
        Object objL = l(obj);
        if (objL == j) {
            return null;
        }
        return objL;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final int size() {
        Map mapE = e();
        return mapE != null ? mapE.size() : this.f;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Collection values() {
        Tt tt = this.i;
        if (tt != null) {
            return tt;
        }
        Tt tt2 = new Tt((Object) this, 3);
        this.i = tt2;
        return tt2;
    }
}
