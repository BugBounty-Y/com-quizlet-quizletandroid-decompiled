package kotlinx.collections.immutable.implementations.immutableList;

import androidx.collection.Y;
import com.android.volley.m;
import com.google.android.gms.internal.mlkit_vision_camera.A1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3413y1;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.ListIterator;
import kotlin.collections.AbstractC4921l;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes3.dex */
public final class d extends AbstractC4921l implements kotlinx.collections.immutable.d {
    public int a;
    public a b;
    public kotlinx.collections.immutable.internal.b c;
    public Object[] d;
    public Object[] e;
    public int f;

    public d(a vector, Object[] objArr, Object[] vectorTail, int i) {
        Intrinsics.checkNotNullParameter(vector, "vector");
        Intrinsics.checkNotNullParameter(vectorTail, "vectorTail");
        this.a = i;
        this.b = vector;
        this.c = new kotlinx.collections.immutable.internal.b();
        this.d = objArr;
        this.e = vectorTail;
        this.f = vector.size();
    }

    public static void g(Object[] objArr, int i, Iterator it2) {
        while (i < 32 && it2.hasNext()) {
            objArr[i] = it2.next();
            i++;
        }
    }

    public final Object[] A(Object[] objArr, int i, int i2, Iterator it2) {
        if (!it2.hasNext()) {
            throw new IllegalStateException("Check failed.");
        }
        if (i2 < 0) {
            throw new IllegalStateException("Check failed.");
        }
        if (i2 == 0) {
            return (Object[]) it2.next();
        }
        Object[] objArrS = s(objArr);
        int iB = AbstractC3413y1.b(i, i2);
        int i3 = i2 - 5;
        objArrS[iB] = A((Object[]) objArrS[iB], i, i3, it2);
        while (true) {
            iB++;
            if (iB >= 32 || !it2.hasNext()) {
                break;
            }
            objArrS[iB] = A((Object[]) objArrS[iB], 0, i3, it2);
        }
        return objArrS;
    }

    public final Object[] C(Object[] objArr, int i, Object[][] objArr2) {
        Y yF = O.f(objArr2);
        int i2 = i >> 5;
        int i3 = this.a;
        Object[] objArrA = i2 < (1 << i3) ? A(objArr, i, i3, yF) : s(objArr);
        while (yF.hasNext()) {
            this.a += 5;
            objArrA = v(objArrA);
            int i4 = this.a;
            A(objArrA, 1 << i4, i4, yF);
        }
        return objArrA;
    }

    public final void E(Object[] objArr, Object[] objArr2, Object[] objArr3) {
        int i = this.f >> 5;
        int i2 = this.a;
        if (i > (1 << i2)) {
            N(F(this.a + 5, v(objArr), objArr2));
            O(objArr3);
            this.a += 5;
            this.f++;
            return;
        }
        if (objArr == null) {
            N(objArr2);
            O(objArr3);
            this.f++;
        } else {
            N(F(i2, objArr, objArr2));
            O(objArr3);
            this.f++;
        }
    }

    public final Object[] F(int i, Object[] objArr, Object[] objArr2) {
        int iB = AbstractC3413y1.b(a() - 1, i);
        Object[] objArrS = s(objArr);
        if (i == 5) {
            objArrS[iB] = objArr2;
            return objArrS;
        }
        objArrS[iB] = F(i - 5, (Object[]) objArrS[iB], objArr2);
        return objArrS;
    }

    public final int G(com.quizlet.ui.compose.modifiers.b bVar, Object[] objArr, int i, int i2, m mVar, ArrayList arrayList, ArrayList arrayList2) {
        if (n(objArr)) {
            arrayList.add(objArr);
        }
        Object obj = mVar.a;
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        Object[] objArr2 = (Object[]) obj;
        Object[] objArrU = objArr2;
        for (int i3 = 0; i3 < i; i3++) {
            Object obj2 = objArr[i3];
            if (!((Boolean) bVar.invoke(obj2)).booleanValue()) {
                if (i2 == 32) {
                    objArrU = !arrayList.isEmpty() ? (Object[]) arrayList.remove(arrayList.size() - 1) : u();
                    i2 = 0;
                }
                objArrU[i2] = obj2;
                i2++;
            }
        }
        mVar.a = objArrU;
        if (objArr2 != objArrU) {
            arrayList2.add(objArr2);
        }
        return i2;
    }

    public final int H(com.quizlet.ui.compose.modifiers.b bVar, Object[] objArr, int i, m mVar) {
        Object[] objArrS = objArr;
        int i2 = i;
        boolean z = false;
        for (int i3 = 0; i3 < i; i3++) {
            Object obj = objArr[i3];
            if (((Boolean) bVar.invoke(obj)).booleanValue()) {
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
        mVar.a = objArrS;
        return i2;
    }

    public final int I(com.quizlet.ui.compose.modifiers.b bVar, int i, m mVar) {
        int iH = H(bVar, this.e, i, mVar);
        if (iH == i) {
            return i;
        }
        Object obj = mVar.a;
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        Object[] objArr = (Object[]) obj;
        Intrinsics.checkNotNullParameter(objArr, "<this>");
        Arrays.fill(objArr, iH, i, (Object) null);
        O(objArr);
        this.f -= i - iH;
        return iH;
    }

    public final Object[] J(Object[] objArr, int i, int i2, m mVar) {
        int iB = AbstractC3413y1.b(i2, i);
        if (i == 0) {
            Object obj = objArr[iB];
            Object[] objArrS = s(objArr);
            C4930v.h(objArr, iB, objArrS, iB + 1, 32);
            objArrS[31] = mVar.a;
            mVar.a = obj;
            return objArrS;
        }
        int iB2 = objArr[31] == null ? AbstractC3413y1.b(L() - 1, i) : 31;
        Object[] objArrS2 = s(objArr);
        int i3 = i - 5;
        int i4 = iB + 1;
        if (i4 <= iB2) {
            while (true) {
                Object obj2 = objArrS2[iB2];
                Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
                objArrS2[iB2] = J((Object[]) obj2, i3, 0, mVar);
                if (iB2 == i4) {
                    break;
                }
                iB2--;
            }
        }
        Object obj3 = objArrS2[iB];
        Intrinsics.e(obj3, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        objArrS2[iB] = J((Object[]) obj3, i3, i2, mVar);
        return objArrS2;
    }

    public final Object K(Object[] objArr, int i, int i2, int i3) {
        int i4 = this.f - i;
        if (i4 == 1) {
            Object obj = this.e[0];
            z(i, i2, objArr);
            return obj;
        }
        Object[] objArr2 = this.e;
        Object obj2 = objArr2[i3];
        Object[] objArrS = s(objArr2);
        C4930v.h(objArr2, i3, objArrS, i3 + 1, i4);
        objArrS[i4 - 1] = null;
        N(objArr);
        O(objArrS);
        this.f = (i + i4) - 1;
        this.a = i2;
        return obj2;
    }

    public final int L() {
        int i = this.f;
        if (i <= 32) {
            return 0;
        }
        return (i - 1) & (-32);
    }

    public final Object[] M(Object[] objArr, int i, int i2, Object obj, m mVar) {
        int iB = AbstractC3413y1.b(i2, i);
        Object[] objArrS = s(objArr);
        if (i != 0) {
            Object obj2 = objArrS[iB];
            Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
            objArrS[iB] = M((Object[]) obj2, i - 5, i2, obj, mVar);
            return objArrS;
        }
        if (objArrS != objArr) {
            ((AbstractList) this).modCount++;
        }
        mVar.a = objArrS[iB];
        objArrS[iB] = obj;
        return objArrS;
    }

    public final void N(Object[] objArr) {
        if (objArr != this.d) {
            this.b = null;
            this.d = objArr;
        }
    }

    public final void O(Object[] objArr) {
        if (objArr != this.e) {
            this.b = null;
            this.e = objArr;
        }
    }

    public final void Q(Collection collection, int i, Object[] objArr, int i2, Object[][] objArr2, int i3, Object[] objArr3) {
        Object[] objArrU;
        if (i3 < 1) {
            throw new IllegalStateException("Check failed.");
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

    public final int R() {
        int i = this.f;
        return i <= 32 ? i : i - ((i - 1) & (-32));
    }

    @Override // kotlin.collections.AbstractC4921l
    public final int a() {
        return this.f;
    }

    @Override // java.util.AbstractList, java.util.List
    public final void add(int i, Object obj) {
        A1.f(i, a());
        if (i == a()) {
            add(obj);
            return;
        }
        ((AbstractList) this).modCount++;
        int iL = L();
        if (i >= iL) {
            m(obj, this.d, i - iL);
            return;
        }
        m mVar = new m(null);
        Object[] objArr = this.d;
        Intrinsics.d(objArr);
        m(mVar.a, j(objArr, this.a, i, obj, mVar), 0);
    }

    @Override // java.util.AbstractList, java.util.List
    public final boolean addAll(int i, Collection elements) {
        Collection collection;
        d dVar;
        Object[] objArrU;
        Intrinsics.checkNotNullParameter(elements, "elements");
        A1.f(i, this.f);
        if (i == this.f) {
            return addAll(elements);
        }
        if (elements.isEmpty()) {
            return false;
        }
        ((AbstractList) this).modCount++;
        int i2 = (i >> 5) << 5;
        int size = ((elements.size() + (this.f - i2)) - 1) / 32;
        if (size == 0) {
            int i3 = i & 31;
            int size2 = ((elements.size() + i) - 1) & 31;
            Object[] objArr = this.e;
            Object[] objArrS = s(objArr);
            C4930v.h(objArr, size2 + 1, objArrS, i3, R());
            g(objArrS, i3, elements.iterator());
            O(objArrS);
            this.f = elements.size() + this.f;
            return true;
        }
        Object[][] objArr2 = new Object[size][];
        int iR = R();
        int size3 = elements.size() + this.f;
        if (size3 > 32) {
            size3 -= (size3 - 1) & (-32);
        }
        if (i >= L()) {
            objArrU = u();
            collection = elements;
            Q(collection, i, this.e, iR, objArr2, size, objArrU);
            dVar = this;
            objArr2 = objArr2;
        } else {
            collection = elements;
            dVar = this;
            if (size3 > iR) {
                int i4 = size3 - iR;
                Object[] objArrT = t(i4, dVar.e);
                dVar.k(collection, i, i4, objArr2, size, objArrT);
                objArr2 = objArr2;
                objArrU = objArrT;
            } else {
                Object[] objArr3 = dVar.e;
                objArrU = u();
                int i5 = iR - size3;
                C4930v.h(objArr3, 0, objArrU, i5, iR);
                int i6 = 32 - i5;
                Object[] objArrT2 = t(i6, dVar.e);
                int i7 = size - 1;
                objArr2[i7] = objArrT2;
                dVar.k(collection, i, i6, objArr2, i7, objArrT2);
                collection = collection;
            }
        }
        N(C(dVar.d, i2, objArr2));
        O(objArrU);
        dVar.f = collection.size() + dVar.f;
        return true;
    }

    @Override // kotlin.collections.AbstractC4921l
    public final Object b(int i) {
        A1.e(i, a());
        ((AbstractList) this).modCount++;
        int iL = L();
        if (i >= iL) {
            return K(this.d, iL, this.a, i - iL);
        }
        m mVar = new m(this.e[0]);
        Object[] objArr = this.d;
        Intrinsics.d(objArr);
        K(J(objArr, this.a, i, mVar), iL, this.a, 0);
        return mVar.a;
    }

    public final kotlinx.collections.immutable.e e() {
        a cVar = this.b;
        if (cVar == null) {
            Object[] objArr = this.d;
            Object[] objArr2 = this.e;
            this.c = new kotlinx.collections.immutable.internal.b();
            if (objArr != null) {
                cVar = new c(objArr, objArr2, this.f, this.a);
            } else if (objArr2.length == 0) {
                cVar = g.c;
            } else {
                Object[] objArrCopyOf = Arrays.copyOf(objArr2, this.f);
                Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
                cVar = new g(objArrCopyOf);
            }
            this.b = cVar;
        }
        return cVar;
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object get(int i) {
        Object[] objArr;
        A1.e(i, a());
        if (L() <= i) {
            objArr = this.e;
        } else {
            objArr = this.d;
            Intrinsics.d(objArr);
            for (int i2 = this.a; i2 > 0; i2 -= 5) {
                Object obj = objArr[AbstractC3413y1.b(i, i2)];
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

    public final Object[] j(Object[] objArr, int i, int i2, Object obj, m mVar) {
        Object obj2;
        int iB = AbstractC3413y1.b(i2, i);
        if (i == 0) {
            mVar.a = objArr[31];
            Object[] objArrS = s(objArr);
            C4930v.h(objArr, iB + 1, objArrS, iB, 31);
            objArrS[iB] = obj;
            return objArrS;
        }
        Object[] objArrS2 = s(objArr);
        int i3 = i - 5;
        Object obj3 = objArrS2[iB];
        Intrinsics.e(obj3, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        objArrS2[iB] = j((Object[]) obj3, i3, i2, obj, mVar);
        while (true) {
            iB++;
            if (iB >= 32 || (obj2 = objArrS2[iB]) == null) {
                break;
            }
            objArrS2[iB] = j((Object[]) obj2, i3, 0, mVar.a, mVar);
        }
        return objArrS2;
    }

    public final void k(Collection collection, int i, int i2, Object[][] objArr, int i3, Object[] objArr2) {
        if (this.d == null) {
            throw new IllegalStateException("Required value was null.");
        }
        int i4 = i >> 5;
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.a aVarO = o(L() >> 5);
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
        int iL = i3 - (((L() >> 5) - 1) - i4);
        if (iL < i3) {
            objArr2 = objArr[iL];
            Intrinsics.d(objArr2);
        }
        Q(collection, i, objArr4, 32, objArr, iL, objArr2);
    }

    @Override // java.util.AbstractList, java.util.List
    public final ListIterator listIterator(int i) {
        A1.f(i, this.f);
        return new f(this, i);
    }

    public final void m(Object obj, Object[] objArr, int i) {
        int iR = R();
        Object[] objArrS = s(this.e);
        if (iR < 32) {
            C4930v.h(this.e, i + 1, objArrS, i, iR);
            objArrS[i] = obj;
            N(objArr);
            O(objArrS);
            this.f++;
            return;
        }
        Object[] objArr2 = this.e;
        Object obj2 = objArr2[31];
        C4930v.h(objArr2, i + 1, objArrS, i, 31);
        objArrS[i] = obj;
        E(objArr, objArrS, v(obj2));
    }

    public final boolean n(Object[] objArr) {
        return objArr.length == 33 && objArr[32] == this.c;
    }

    public final androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.a o(int i) {
        if (this.d == null) {
            throw new IllegalStateException("Required value was null.");
        }
        int iL = L() >> 5;
        A1.f(i, iL);
        int i2 = this.a;
        if (i2 == 0) {
            Object[] objArr = this.d;
            Intrinsics.d(objArr);
            return new b(objArr, i);
        }
        Object[] objArr2 = this.d;
        Intrinsics.d(objArr2);
        return new h(objArr2, i, iL, i2 / 5);
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0032, code lost:
    
        r2 = r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x0060, code lost:
    
        if (r0 != r15) goto L9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:8:0x002c, code lost:
    
        if (I(r3, r15, r7) != r15) goto L9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:9:0x002e, code lost:
    
        r2 = r14;
     */
    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean removeAll(java.util.Collection r15) {
        /*
            Method dump skipped, instructions count: 252
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.collections.immutable.implementations.immutableList.d.removeAll(java.util.Collection):boolean");
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
        A1.e(i, a());
        if (L() > i) {
            m mVar = new m(null);
            Object[] objArr = this.d;
            Intrinsics.d(objArr);
            N(M(objArr, this.a, i, obj, mVar));
            return mVar.a;
        }
        Object[] objArrS = s(this.e);
        if (objArrS != this.e) {
            ((AbstractList) this).modCount++;
        }
        int i2 = i & 31;
        Object obj2 = objArrS[i2];
        objArrS[i2] = obj;
        O(objArrS);
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
        objArr[32] = this.c;
        return objArr;
    }

    public final Object[] v(Object obj) {
        Object[] objArr = new Object[33];
        objArr[0] = obj;
        objArr[32] = this.c;
        return objArr;
    }

    public final Object[] w(int i, int i2, Object[] objArr) {
        if (i2 < 0) {
            throw new IllegalStateException("Check failed.");
        }
        if (i2 == 0) {
            return objArr;
        }
        int iB = AbstractC3413y1.b(i, i2);
        Object obj = objArr[iB];
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        Object objW = w(i, i2 - 5, (Object[]) obj);
        if (iB < 31) {
            int i3 = iB + 1;
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
        if (objW == objArr[iB]) {
            return objArr;
        }
        Object[] objArrS = s(objArr);
        objArrS[iB] = objW;
        return objArrS;
    }

    public final Object[] x(Object[] objArr, int i, int i2, m mVar) {
        Object[] objArrX;
        int iB = AbstractC3413y1.b(i2 - 1, i);
        if (i == 5) {
            mVar.a = objArr[iB];
            objArrX = null;
        } else {
            Object obj = objArr[iB];
            Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
            objArrX = x((Object[]) obj, i - 5, i2, mVar);
        }
        if (objArrX == null && iB == 0) {
            return null;
        }
        Object[] objArrS = s(objArr);
        objArrS[iB] = objArrX;
        return objArrS;
    }

    public final void z(int i, int i2, Object[] objArr) {
        Object obj = null;
        if (i2 == 0) {
            N(null);
            if (objArr == null) {
                objArr = new Object[0];
            }
            O(objArr);
            this.f = i;
            this.a = i2;
            return;
        }
        m mVar = new m(obj);
        Intrinsics.d(objArr);
        Object[] objArrX = x(objArr, i2, i, mVar);
        Intrinsics.d(objArrX);
        Object obj2 = mVar.a;
        Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        O((Object[]) obj2);
        this.f = i;
        if (objArrX[1] == null) {
            N((Object[]) objArrX[0]);
            this.a = i2 - 5;
        } else {
            N(objArrX);
            this.a = i2;
        }
    }

    @Override // java.util.AbstractList, java.util.List
    public final ListIterator listIterator() {
        return listIterator(0);
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean add(Object obj) {
        ((AbstractList) this).modCount++;
        int iR = R();
        if (iR < 32) {
            Object[] objArrS = s(this.e);
            objArrS[iR] = obj;
            O(objArrS);
            this.f = a() + 1;
        } else {
            E(this.d, this.e, v(obj));
        }
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean addAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        if (elements.isEmpty()) {
            return false;
        }
        ((AbstractList) this).modCount++;
        int iR = R();
        Iterator it2 = elements.iterator();
        if (32 - iR >= elements.size()) {
            Object[] objArrS = s(this.e);
            g(objArrS, iR, it2);
            O(objArrS);
            this.f = elements.size() + this.f;
            return true;
        }
        int size = ((elements.size() + iR) - 1) / 32;
        Object[][] objArr = new Object[size][];
        Object[] objArrS2 = s(this.e);
        g(objArrS2, iR, it2);
        objArr[0] = objArrS2;
        for (int i = 1; i < size; i++) {
            Object[] objArrU = u();
            g(objArrU, 0, it2);
            objArr[i] = objArrU;
        }
        N(C(this.d, L(), objArr));
        Object[] objArrU2 = u();
        g(objArrU2, 0, it2);
        O(objArrU2);
        this.f = elements.size() + this.f;
        return true;
    }
}
