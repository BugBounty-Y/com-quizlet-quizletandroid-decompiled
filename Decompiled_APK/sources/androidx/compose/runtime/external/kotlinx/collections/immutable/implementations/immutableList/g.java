package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList;

import androidx.collection.Y;
import androidx.compose.runtime.AbstractC0805k0;
import com.google.android.gms.internal.mlkit_vision_barcode.G4;
import com.google.android.gms.internal.mlkit_vision_barcode.I4;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.ListIterator;
import kotlin.collections.AbstractC4921l;
import kotlin.collections.C4930v;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes.dex */
public final class g extends AbstractC4921l implements Collection, kotlin.jvm.internal.markers.b {
    public androidx.compose.runtime.external.kotlinx.collections.immutable.c a;
    public Object[] b;
    public Object[] c;
    public int d;
    public androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b e = new androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b();
    public Object[] f;
    public Object[] g;
    public int h;

    public g(c cVar, Object[] objArr, Object[] objArr2, int i) {
        this.a = cVar;
        this.b = objArr;
        this.c = objArr2;
        this.d = i;
        this.f = objArr;
        this.g = objArr2;
        this.h = cVar.size();
    }

    public static void g(Object[] objArr, int i, Iterator it2) {
        while (i < 32 && it2.hasNext()) {
            objArr[i] = it2.next();
            i++;
        }
    }

    public final Object[] A(Object[] objArr, int i, int i2, Iterator it2) {
        if (!it2.hasNext()) {
            AbstractC0805k0.a("invalid buffersIterator");
        }
        if (!(i2 >= 0)) {
            AbstractC0805k0.a("negative shift");
        }
        if (i2 == 0) {
            return (Object[]) it2.next();
        }
        Object[] objArrS = s(objArr);
        int iF = G4.f(i, i2);
        int i3 = i2 - 5;
        objArrS[iF] = A((Object[]) objArrS[iF], i, i3, it2);
        while (true) {
            iF++;
            if (iF >= 32 || !it2.hasNext()) {
                break;
            }
            objArrS[iF] = A((Object[]) objArrS[iF], 0, i3, it2);
        }
        return objArrS;
    }

    public final Object[] C(Object[] objArr, int i, Object[][] objArr2) {
        Y yF = O.f(objArr2);
        int i2 = i >> 5;
        int i3 = this.d;
        Object[] objArrA = i2 < (1 << i3) ? A(objArr, i, i3, yF) : s(objArr);
        while (yF.hasNext()) {
            this.d += 5;
            objArrA = v(objArrA);
            int i4 = this.d;
            A(objArrA, 1 << i4, i4, yF);
        }
        return objArrA;
    }

    public final void E(Object[] objArr, Object[] objArr2, Object[] objArr3) {
        int i = this.h;
        int i2 = i >> 5;
        int i3 = this.d;
        if (i2 > (1 << i3)) {
            this.f = F(this.d + 5, v(objArr), objArr2);
            this.g = objArr3;
            this.d += 5;
            this.h++;
            return;
        }
        if (objArr == null) {
            this.f = objArr2;
            this.g = objArr3;
            this.h = i + 1;
        } else {
            this.f = F(i3, objArr, objArr2);
            this.g = objArr3;
            this.h++;
        }
    }

    public final Object[] F(int i, Object[] objArr, Object[] objArr2) {
        int iF = G4.f(a() - 1, i);
        Object[] objArrS = s(objArr);
        if (i == 5) {
            objArrS[iF] = objArr2;
            return objArrS;
        }
        objArrS[iF] = F(i - 5, (Object[]) objArrS[iF], objArr2);
        return objArrS;
    }

    public final int G(Function1 function1, Object[] objArr, int i, int i2, e eVar, ArrayList arrayList, ArrayList arrayList2) {
        if (n(objArr)) {
            arrayList.add(objArr);
        }
        Object obj = eVar.a;
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        Object[] objArr2 = (Object[]) obj;
        Object[] objArrU = objArr2;
        for (int i3 = 0; i3 < i; i3++) {
            Object obj2 = objArr[i3];
            if (!((Boolean) function1.invoke(obj2)).booleanValue()) {
                if (i2 == 32) {
                    objArrU = !arrayList.isEmpty() ? (Object[]) arrayList.remove(arrayList.size() - 1) : u();
                    i2 = 0;
                }
                objArrU[i2] = obj2;
                i2++;
            }
        }
        eVar.a = objArrU;
        if (objArr2 != objArrU) {
            arrayList2.add(objArr2);
        }
        return i2;
    }

    public final int H(Function1 function1, Object[] objArr, int i, e eVar) {
        Object[] objArrS = objArr;
        int i2 = i;
        boolean z = false;
        for (int i3 = 0; i3 < i; i3++) {
            Object obj = objArr[i3];
            if (((Boolean) function1.invoke(obj)).booleanValue()) {
                if (!z) {
                    objArrS = s(objArr);
                    z = true;
                    i2 = i3;
                }
            } else if (z) {
                objArrS[i2] = obj;
                i2++;
            }
        }
        eVar.a = objArrS;
        return i2;
    }

    public final int I(Function1 function1, int i, e eVar) {
        int iH = H(function1, this.g, i, eVar);
        if (iH == i) {
            return i;
        }
        Object obj = eVar.a;
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        Object[] objArr = (Object[]) obj;
        Intrinsics.checkNotNullParameter(objArr, "<this>");
        Arrays.fill(objArr, iH, i, (Object) null);
        this.g = objArr;
        this.h -= i - iH;
        return iH;
    }

    public final boolean J(Function1 function1) {
        Object[] objArrA;
        int i;
        Function1 function12 = function1;
        int iQ = Q();
        Object[] objArrW = null;
        e eVar = new e(null);
        boolean z = false;
        if (this.f != null) {
            a aVarO = o(0);
            int iH = 32;
            while (iH == 32 && aVarO.hasNext()) {
                iH = H(function12, (Object[]) aVarO.next(), 32, eVar);
            }
            if (iH == 32) {
                int I = I(function12, iQ, eVar);
                if (I == 0) {
                    z(this.h, this.d, this.f);
                }
                if (I != iQ) {
                }
            } else {
                int i2 = (aVarO.b - 1) << 5;
                ArrayList arrayList = new ArrayList();
                ArrayList arrayList2 = new ArrayList();
                int iG = iH;
                while (aVarO.hasNext()) {
                    iG = G(function12, (Object[]) aVarO.next(), 32, iG, eVar, arrayList2, arrayList);
                    function12 = function1;
                }
                int iG2 = G(function1, this.g, iQ, iG, eVar, arrayList2, arrayList);
                Object obj = eVar.a;
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
                Object[] objArr = (Object[]) obj;
                Intrinsics.checkNotNullParameter(objArr, "<this>");
                Arrays.fill(objArr, iG2, 32, (Object) null);
                if (arrayList.isEmpty()) {
                    objArrA = this.f;
                    Intrinsics.d(objArrA);
                } else {
                    objArrA = A(this.f, i2, this.d, arrayList.iterator());
                }
                int size = i2 + (arrayList.size() << 5);
                if ((size & 31) != 0) {
                    AbstractC0805k0.a("invalid size");
                }
                if (size == 0) {
                    this.d = 0;
                } else {
                    int i3 = size - 1;
                    while (true) {
                        i = this.d;
                        if ((i3 >> i) != 0) {
                            break;
                        }
                        this.d = i - 5;
                        Object[] objArr2 = objArrA[0];
                        Intrinsics.e(objArr2, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
                        objArrA = objArr2;
                    }
                    objArrW = w(i3, i, objArrA);
                }
                this.f = objArrW;
                this.g = objArr;
                this.h = size + iG2;
            }
            z = true;
        } else if (I(function12, iQ, eVar) != iQ) {
            z = true;
        }
        if (z) {
            ((AbstractList) this).modCount++;
        }
        return z;
    }

    public final Object[] K(Object[] objArr, int i, int i2, e eVar) {
        int iF = G4.f(i2, i);
        if (i == 0) {
            Object obj = objArr[iF];
            Object[] objArrS = s(objArr);
            C4930v.h(objArr, iF, objArrS, iF + 1, 32);
            objArrS[31] = eVar.a;
            eVar.a = obj;
            return objArrS;
        }
        int iF2 = objArr[31] == null ? G4.f(M() - 1, i) : 31;
        Object[] objArrS2 = s(objArr);
        int i3 = i - 5;
        int i4 = iF + 1;
        if (i4 <= iF2) {
            while (true) {
                Object obj2 = objArrS2[iF2];
                Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
                objArrS2[iF2] = K((Object[]) obj2, i3, 0, eVar);
                if (iF2 == i4) {
                    break;
                }
                iF2--;
            }
        }
        Object obj3 = objArrS2[iF];
        Intrinsics.e(obj3, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        objArrS2[iF] = K((Object[]) obj3, i3, i2, eVar);
        return objArrS2;
    }

    public final Object L(Object[] objArr, int i, int i2, int i3) {
        int i4 = this.h - i;
        if (i4 == 1) {
            Object obj = this.g[0];
            z(i, i2, objArr);
            return obj;
        }
        Object[] objArr2 = this.g;
        Object obj2 = objArr2[i3];
        Object[] objArrS = s(objArr2);
        C4930v.h(objArr2, i3, objArrS, i3 + 1, i4);
        objArrS[i4 - 1] = null;
        this.f = objArr;
        this.g = objArrS;
        this.h = (i + i4) - 1;
        this.d = i2;
        return obj2;
    }

    public final int M() {
        int i = this.h;
        if (i <= 32) {
            return 0;
        }
        return (i - 1) & (-32);
    }

    public final Object[] N(Object[] objArr, int i, int i2, Object obj, e eVar) {
        int iF = G4.f(i2, i);
        Object[] objArrS = s(objArr);
        if (i != 0) {
            Object obj2 = objArrS[iF];
            Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
            objArrS[iF] = N((Object[]) obj2, i - 5, i2, obj, eVar);
            return objArrS;
        }
        if (objArrS != objArr) {
            ((AbstractList) this).modCount++;
        }
        eVar.a = objArrS[iF];
        objArrS[iF] = obj;
        return objArrS;
    }

    public final void O(Collection collection, int i, Object[] objArr, int i2, Object[][] objArr2, int i3, Object[] objArr3) {
        Object[] objArrU;
        if (i3 < 1) {
            AbstractC0805k0.a("requires at least one nullBuffer");
        }
        Object[] objArrS = s(objArr);
        objArr2[0] = objArrS;
        int i4 = i & 31;
        int size = ((collection.size() + i) - 1) & 31;
        int i5 = (i2 - i4) + size;
        if (i5 < 32) {
            C4930v.h(objArrS, size + 1, objArr3, i4, i2);
        } else {
            int i6 = i5 - 31;
            if (i3 == 1) {
                objArrU = objArrS;
            } else {
                objArrU = u();
                i3--;
                objArr2[i3] = objArrU;
            }
            int i7 = i2 - i6;
            C4930v.h(objArrS, 0, objArr3, i7, i2);
            C4930v.h(objArrS, size + 1, objArrU, i4, i7);
            objArr3 = objArrU;
        }
        Iterator it2 = collection.iterator();
        g(objArrS, i4, it2);
        for (int i8 = 1; i8 < i3; i8++) {
            Object[] objArrU2 = u();
            g(objArrU2, 0, it2);
            objArr2[i8] = objArrU2;
        }
        g(objArr3, 0, it2);
    }

    public final int Q() {
        int i = this.h;
        return i <= 32 ? i : i - ((i - 1) & (-32));
    }

    @Override // kotlin.collections.AbstractC4921l
    public final int a() {
        return this.h;
    }

    @Override // java.util.AbstractList, java.util.List
    public final void add(int i, Object obj) {
        I4.c(i, a());
        if (i == a()) {
            add(obj);
            return;
        }
        ((AbstractList) this).modCount++;
        int iM = M();
        if (i >= iM) {
            m(obj, this.f, i - iM);
            return;
        }
        e eVar = new e(null);
        Object[] objArr = this.f;
        Intrinsics.d(objArr);
        m(eVar.a, k(objArr, this.d, i, obj, eVar), 0);
    }

    @Override // java.util.AbstractList, java.util.List
    public final boolean addAll(int i, Collection collection) {
        Collection collection2;
        g gVar;
        Object[] objArrU;
        I4.c(i, this.h);
        if (i == this.h) {
            return addAll(collection);
        }
        if (collection.isEmpty()) {
            return false;
        }
        ((AbstractList) this).modCount++;
        int i2 = (i >> 5) << 5;
        int size = ((collection.size() + (this.h - i2)) - 1) / 32;
        if (size == 0) {
            int i3 = i & 31;
            int size2 = ((collection.size() + i) - 1) & 31;
            Object[] objArr = this.g;
            Object[] objArrS = s(objArr);
            C4930v.h(objArr, size2 + 1, objArrS, i3, Q());
            g(objArrS, i3, collection.iterator());
            this.g = objArrS;
            this.h = collection.size() + this.h;
            return true;
        }
        Object[][] objArr2 = new Object[size][];
        int iQ = Q();
        int size3 = collection.size() + this.h;
        if (size3 > 32) {
            size3 -= (size3 - 1) & (-32);
        }
        if (i >= M()) {
            objArrU = u();
            collection2 = collection;
            O(collection2, i, this.g, iQ, objArr2, size, objArrU);
            gVar = this;
            objArr2 = objArr2;
        } else {
            collection2 = collection;
            gVar = this;
            if (size3 > iQ) {
                int i4 = size3 - iQ;
                Object[] objArrT = t(i4, gVar.g);
                gVar.j(collection2, i, i4, objArr2, size, objArrT);
                objArr2 = objArr2;
                objArrU = objArrT;
            } else {
                Object[] objArr3 = gVar.g;
                objArrU = u();
                int i5 = iQ - size3;
                C4930v.h(objArr3, 0, objArrU, i5, iQ);
                int i6 = 32 - i5;
                Object[] objArrT2 = t(i6, gVar.g);
                int i7 = size - 1;
                objArr2[i7] = objArrT2;
                gVar.j(collection2, i, i6, objArr2, i7, objArrT2);
                collection2 = collection2;
            }
        }
        gVar.f = C(gVar.f, i2, objArr2);
        gVar.g = objArrU;
        gVar.h = collection2.size() + gVar.h;
        return true;
    }

    @Override // kotlin.collections.AbstractC4921l
    public final Object b(int i) {
        I4.b(i, a());
        ((AbstractList) this).modCount++;
        int iM = M();
        if (i >= iM) {
            return L(this.f, iM, this.d, i - iM);
        }
        e eVar = new e(this.g[0]);
        Object[] objArr = this.f;
        Intrinsics.d(objArr);
        L(K(objArr, this.d, i, eVar), iM, this.d, 0);
        return eVar.a;
    }

    public final androidx.compose.runtime.external.kotlinx.collections.immutable.c e() {
        androidx.compose.runtime.external.kotlinx.collections.immutable.c fVar;
        Object[] objArr = this.f;
        if (objArr == this.b && this.g == this.c) {
            fVar = this.a;
        } else {
            this.e = new androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b();
            this.b = objArr;
            Object[] objArr2 = this.g;
            this.c = objArr2;
            if (objArr != null) {
                Object[] objArr3 = this.f;
                Intrinsics.d(objArr3);
                fVar = new f(objArr3, this.g, a(), this.d);
            } else if (objArr2.length == 0) {
                fVar = j.c;
            } else {
                Object[] objArrCopyOf = Arrays.copyOf(this.g, a());
                Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
                fVar = new j(objArrCopyOf);
            }
        }
        this.a = fVar;
        return fVar;
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object get(int i) {
        Object[] objArr;
        I4.b(i, a());
        if (M() <= i) {
            objArr = this.g;
        } else {
            objArr = this.f;
            Intrinsics.d(objArr);
            for (int i2 = this.d; i2 > 0; i2 -= 5) {
                Object obj = objArr[G4.f(i, i2)];
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
                objArr = (Object[]) obj;
            }
        }
        return objArr[i & 31];
    }

    public final int h() {
        return ((AbstractList) this).modCount;
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.List
    public final Iterator iterator() {
        return listIterator(0);
    }

    public final void j(Collection collection, int i, int i2, Object[][] objArr, int i3, Object[] objArr2) {
        if (this.f == null) {
            throw new IllegalStateException("root is null");
        }
        int i4 = i >> 5;
        a aVarO = o(M() >> 5);
        int i5 = i3;
        Object[] objArrT = objArr2;
        while (aVarO.b - 1 != i4) {
            Object[] objArr3 = (Object[]) aVarO.previous();
            C4930v.h(objArr3, 0, objArrT, 32 - i2, 32);
            objArrT = t(i2, objArr3);
            i5--;
            objArr[i5] = objArrT;
        }
        Object[] objArr4 = (Object[]) aVarO.previous();
        int iM = i3 - (((M() >> 5) - 1) - i4);
        if (iM < i3) {
            objArr2 = objArr[iM];
            Intrinsics.d(objArr2);
        }
        O(collection, i, objArr4, 32, objArr, iM, objArr2);
    }

    public final Object[] k(Object[] objArr, int i, int i2, Object obj, e eVar) {
        Object obj2;
        int iF = G4.f(i2, i);
        if (i == 0) {
            eVar.a = objArr[31];
            Object[] objArrS = s(objArr);
            C4930v.h(objArr, iF + 1, objArrS, iF, 31);
            objArrS[iF] = obj;
            return objArrS;
        }
        Object[] objArrS2 = s(objArr);
        int i3 = i - 5;
        Object obj3 = objArrS2[iF];
        Intrinsics.e(obj3, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        objArrS2[iF] = k((Object[]) obj3, i3, i2, obj, eVar);
        while (true) {
            iF++;
            if (iF >= 32 || (obj2 = objArrS2[iF]) == null) {
                break;
            }
            objArrS2[iF] = k((Object[]) obj2, i3, 0, eVar.a, eVar);
        }
        return objArrS2;
    }

    @Override // java.util.AbstractList, java.util.List
    public final ListIterator listIterator(int i) {
        I4.c(i, this.h);
        return new i(this, i);
    }

    public final void m(Object obj, Object[] objArr, int i) {
        int iQ = Q();
        Object[] objArrS = s(this.g);
        if (iQ < 32) {
            C4930v.h(this.g, i + 1, objArrS, i, iQ);
            objArrS[i] = obj;
            this.f = objArr;
            this.g = objArrS;
            this.h++;
            return;
        }
        Object[] objArr2 = this.g;
        Object obj2 = objArr2[31];
        C4930v.h(objArr2, i + 1, objArrS, i, 31);
        objArrS[i] = obj;
        E(objArr, objArrS, v(obj2));
    }

    public final boolean n(Object[] objArr) {
        return objArr.length == 33 && objArr[32] == this.e;
    }

    public final a o(int i) {
        Object[] objArr = this.f;
        if (objArr == null) {
            throw new IllegalStateException("Invalid root");
        }
        int iM = M() >> 5;
        I4.c(i, iM);
        int i2 = this.d;
        return i2 == 0 ? new d(objArr, i) : new k(objArr, i, iM, i2 / 5);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean removeAll(Collection collection) {
        return J(new b(1, collection));
    }

    public final Object[] s(Object[] objArr) {
        if (objArr == null) {
            return u();
        }
        if (n(objArr)) {
            return objArr;
        }
        Object[] objArrU = u();
        int length = objArr.length;
        if (length > 32) {
            length = 32;
        }
        C4930v.j(objArr, 0, objArrU, length, 6);
        return objArrU;
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object set(int i, Object obj) {
        I4.b(i, a());
        if (M() > i) {
            e eVar = new e(null);
            Object[] objArr = this.f;
            Intrinsics.d(objArr);
            this.f = N(objArr, this.d, i, obj, eVar);
            return eVar.a;
        }
        Object[] objArrS = s(this.g);
        if (objArrS != this.g) {
            ((AbstractList) this).modCount++;
        }
        int i2 = i & 31;
        Object obj2 = objArrS[i2];
        objArrS[i2] = obj;
        this.g = objArrS;
        return obj2;
    }

    public final Object[] t(int i, Object[] objArr) {
        if (n(objArr)) {
            C4930v.h(objArr, i, objArr, 0, 32 - i);
            return objArr;
        }
        Object[] objArrU = u();
        C4930v.h(objArr, i, objArrU, 0, 32 - i);
        return objArrU;
    }

    public final Object[] u() {
        Object[] objArr = new Object[33];
        objArr[32] = this.e;
        return objArr;
    }

    public final Object[] v(Object obj) {
        Object[] objArr = new Object[33];
        objArr[0] = obj;
        objArr[32] = this.e;
        return objArr;
    }

    public final Object[] w(int i, int i2, Object[] objArr) {
        if (i2 < 0) {
            AbstractC0805k0.a("shift should be positive");
        }
        if (i2 == 0) {
            return objArr;
        }
        int iF = G4.f(i, i2);
        Object obj = objArr[iF];
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        Object objW = w(i, i2 - 5, (Object[]) obj);
        if (iF < 31) {
            int i3 = iF + 1;
            if (objArr[i3] != null) {
                if (n(objArr)) {
                    Intrinsics.checkNotNullParameter(objArr, "<this>");
                    Arrays.fill(objArr, i3, 32, (Object) null);
                }
                Object[] objArrU = u();
                C4930v.h(objArr, 0, objArrU, 0, i3);
                objArr = objArrU;
            }
        }
        if (objW == objArr[iF]) {
            return objArr;
        }
        Object[] objArrS = s(objArr);
        objArrS[iF] = objW;
        return objArrS;
    }

    public final Object[] x(Object[] objArr, int i, int i2, e eVar) {
        Object[] objArrX;
        int iF = G4.f(i2 - 1, i);
        if (i == 5) {
            eVar.a = objArr[iF];
            objArrX = null;
        } else {
            Object obj = objArr[iF];
            Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
            objArrX = x((Object[]) obj, i - 5, i2, eVar);
        }
        if (objArrX == null && iF == 0) {
            return null;
        }
        Object[] objArrS = s(objArr);
        objArrS[iF] = objArrX;
        return objArrS;
    }

    public final void z(int i, int i2, Object[] objArr) {
        if (i2 == 0) {
            this.f = null;
            if (objArr == null) {
                objArr = new Object[0];
            }
            this.g = objArr;
            this.h = i;
            this.d = i2;
            return;
        }
        e eVar = new e(null);
        Intrinsics.d(objArr);
        Object[] objArrX = x(objArr, i2, i, eVar);
        Intrinsics.d(objArrX);
        Object obj = eVar.a;
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        this.g = (Object[]) obj;
        this.h = i;
        if (objArrX[1] == null) {
            this.f = (Object[]) objArrX[0];
            this.d = i2 - 5;
        } else {
            this.f = objArrX;
            this.d = i2;
        }
    }

    @Override // java.util.AbstractList, java.util.List
    public final ListIterator listIterator() {
        return listIterator(0);
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean add(Object obj) {
        ((AbstractList) this).modCount++;
        int iQ = Q();
        if (iQ < 32) {
            Object[] objArrS = s(this.g);
            objArrS[iQ] = obj;
            this.g = objArrS;
            this.h = a() + 1;
        } else {
            E(this.f, this.g, v(obj));
        }
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean addAll(Collection collection) {
        if (collection.isEmpty()) {
            return false;
        }
        ((AbstractList) this).modCount++;
        int iQ = Q();
        Iterator it2 = collection.iterator();
        if (32 - iQ >= collection.size()) {
            Object[] objArrS = s(this.g);
            g(objArrS, iQ, it2);
            this.g = objArrS;
            this.h = collection.size() + this.h;
            return true;
        }
        int size = ((collection.size() + iQ) - 1) / 32;
        Object[][] objArr = new Object[size][];
        Object[] objArrS2 = s(this.g);
        g(objArrS2, iQ, it2);
        objArr[0] = objArrS2;
        for (int i = 1; i < size; i++) {
            Object[] objArrU = u();
            g(objArrU, 0, it2);
            objArr[i] = objArrU;
        }
        this.f = C(this.f, M(), objArr);
        Object[] objArrU2 = u();
        g(objArrU2, 0, it2);
        this.g = objArrU2;
        this.h = collection.size() + this.h;
        return true;
    }
}
