package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList;

import androidx.compose.runtime.AbstractC0805k0;
import com.google.android.gms.internal.mlkit_vision_barcode.G4;
import com.google.android.gms.internal.mlkit_vision_barcode.I4;
import java.util.Arrays;
import java.util.ListIterator;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f extends c {
    public final Object[] b;
    public final Object[] c;
    public final int d;
    public final int e;

    public f(Object[] objArr, Object[] objArr2, int i, int i2) {
        this.b = objArr;
        this.c = objArr2;
        this.d = i;
        this.e = i2;
        if (!(a() > 32)) {
            AbstractC0805k0.a("Trie-based persistent vector should have at least 33 elements, got " + a());
        }
        int length = objArr2.length;
    }

    public static Object[] b(Object[] objArr, int i, int i2, Object obj, e eVar) {
        Object[] objArrCopyOf;
        int iF = G4.f(i2, i);
        if (i == 0) {
            if (iF == 0) {
                objArrCopyOf = new Object[32];
            } else {
                objArrCopyOf = Arrays.copyOf(objArr, 32);
                Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            }
            C4930v.h(objArr, iF + 1, objArrCopyOf, iF, 31);
            eVar.a = objArr[31];
            objArrCopyOf[iF] = obj;
            return objArrCopyOf;
        }
        Object[] objArrCopyOf2 = Arrays.copyOf(objArr, 32);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf2, "copyOf(...)");
        int i3 = i - 5;
        Object obj2 = objArr[iF];
        Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        objArrCopyOf2[iF] = b((Object[]) obj2, i3, i2, obj, eVar);
        while (true) {
            iF++;
            if (iF >= 32 || objArrCopyOf2[iF] == null) {
                break;
            }
            Object obj3 = objArr[iF];
            Intrinsics.e(obj3, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
            objArrCopyOf2[iF] = b((Object[]) obj3, i3, 0, eVar.a, eVar);
        }
        return objArrCopyOf2;
    }

    public static Object[] g(Object[] objArr, int i, int i2, e eVar) {
        Object[] objArrG;
        int iF = G4.f(i2, i);
        if (i == 5) {
            eVar.a = objArr[iF];
            objArrG = null;
        } else {
            Object obj = objArr[iF];
            Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
            objArrG = g((Object[]) obj, i - 5, i2, eVar);
        }
        if (objArrG == null && iF == 0) {
            return null;
        }
        Object[] objArrCopyOf = Arrays.copyOf(objArr, 32);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
        objArrCopyOf[iF] = objArrG;
        return objArrCopyOf;
    }

    public static Object[] o(Object obj, int i, Object[] objArr, int i2) {
        int iF = G4.f(i2, i);
        Object[] objArrCopyOf = Arrays.copyOf(objArr, 32);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
        if (i == 0) {
            objArrCopyOf[iF] = obj;
            return objArrCopyOf;
        }
        Object obj2 = objArrCopyOf[iF];
        Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        objArrCopyOf[iF] = o(obj, i - 5, (Object[]) obj2, i2);
        return objArrCopyOf;
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.c Y(b bVar) {
        g gVar = new g(this, this.b, this.c, this.e);
        gVar.J(bVar);
        return gVar.e();
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.d;
    }

    @Override // java.util.Collection, java.util.List, androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.c add(Object obj) {
        int iN = n();
        int i = this.d;
        int i2 = i - iN;
        Object[] objArr = this.b;
        Object[] objArr2 = this.c;
        if (i2 >= 32) {
            Object[] objArr3 = new Object[32];
            objArr3[0] = obj;
            return h(objArr, objArr2, objArr3);
        }
        Object[] objArrCopyOf = Arrays.copyOf(objArr2, 32);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
        objArrCopyOf[i2] = obj;
        return new f(objArr, objArrCopyOf, i + 1, this.e);
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final g builder() {
        return new g(this, this.b, this.c, this.e);
    }

    public final f e(Object obj, Object[] objArr, int i) {
        int iN = n();
        int i2 = this.d;
        int i3 = i2 - iN;
        Object[] objArr2 = this.c;
        Object[] objArrCopyOf = Arrays.copyOf(objArr2, 32);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
        if (i3 < 32) {
            C4930v.h(objArr2, i + 1, objArrCopyOf, i, i3);
            objArrCopyOf[i] = obj;
            return new f(objArr, objArrCopyOf, i2 + 1, this.e);
        }
        Object obj2 = objArr2[31];
        C4930v.h(objArr2, i + 1, objArrCopyOf, i, i3 - 1);
        objArrCopyOf[i] = obj;
        Object[] objArr3 = new Object[32];
        objArr3[0] = obj2;
        return h(objArr, objArrCopyOf, objArr3);
    }

    @Override // java.util.List
    public final Object get(int i) {
        Object[] objArr;
        I4.b(i, a());
        if (n() <= i) {
            objArr = this.c;
        } else {
            objArr = this.b;
            for (int i2 = this.e; i2 > 0; i2 -= 5) {
                Object obj = objArr[G4.f(i, i2)];
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
                objArr = (Object[]) obj;
            }
        }
        return objArr[i & 31];
    }

    public final f h(Object[] objArr, Object[] objArr2, Object[] objArr3) {
        int i = this.d;
        int i2 = i >> 5;
        int i3 = this.e;
        if (i2 <= (1 << i3)) {
            return new f(j(i3, objArr, objArr2), objArr3, i + 1, i3);
        }
        Object[] objArr4 = new Object[32];
        objArr4[0] = objArr;
        int i4 = i3 + 5;
        return new f(j(i4, objArr4, objArr2), objArr3, i + 1, i4);
    }

    /* JADX WARN: Removed duplicated region for block: B:6:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object[] j(int r4, java.lang.Object[] r5, java.lang.Object[] r6) {
        /*
            r3 = this;
            int r0 = r3.a()
            int r0 = r0 + (-1)
            int r0 = com.google.android.gms.internal.mlkit_vision_barcode.G4.f(r0, r4)
            r1 = 32
            if (r5 == 0) goto L19
            java.lang.Object[] r5 = java.util.Arrays.copyOf(r5, r1)
            java.lang.String r2 = "copyOf(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r2)
            if (r5 != 0) goto L1b
        L19:
            java.lang.Object[] r5 = new java.lang.Object[r1]
        L1b:
            r1 = 5
            if (r4 != r1) goto L21
            r5[r0] = r6
            return r5
        L21:
            r2 = r5[r0]
            java.lang.Object[] r2 = (java.lang.Object[]) r2
            int r4 = r4 - r1
            java.lang.Object[] r4 = r3.j(r4, r2, r6)
            r5[r0] = r4
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.f.j(int, java.lang.Object[], java.lang.Object[]):java.lang.Object[]");
    }

    public final Object[] k(Object[] objArr, int i, int i2, e eVar) {
        Object[] objArrCopyOf;
        int iF = G4.f(i2, i);
        if (i == 0) {
            if (iF == 0) {
                objArrCopyOf = new Object[32];
            } else {
                objArrCopyOf = Arrays.copyOf(objArr, 32);
                Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            }
            C4930v.h(objArr, iF, objArrCopyOf, iF + 1, 32);
            objArrCopyOf[31] = eVar.a;
            eVar.a = objArr[iF];
            return objArrCopyOf;
        }
        int iF2 = objArr[31] == null ? G4.f(n() - 1, i) : 31;
        Object[] objArrCopyOf2 = Arrays.copyOf(objArr, 32);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf2, "copyOf(...)");
        int i3 = i - 5;
        int i4 = iF + 1;
        if (i4 <= iF2) {
            while (true) {
                Object obj = objArrCopyOf2[iF2];
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
                objArrCopyOf2[iF2] = k((Object[]) obj, i3, 0, eVar);
                if (iF2 == i4) {
                    break;
                }
                iF2--;
            }
        }
        Object obj2 = objArrCopyOf2[iF];
        Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        objArrCopyOf2[iF] = k((Object[]) obj2, i3, i2, eVar);
        return objArrCopyOf2;
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final ListIterator listIterator(int i) {
        I4.c(i, this.d);
        return new h(this.b, i, this.c, this.d, (this.e / 5) + 1);
    }

    public final c m(Object[] objArr, int i, int i2, int i3) {
        int i4 = this.d - i;
        if (i4 != 1) {
            Object[] objArr2 = this.c;
            Object[] objArrCopyOf = Arrays.copyOf(objArr2, 32);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            int i5 = i4 - 1;
            if (i3 < i5) {
                C4930v.h(objArr2, i3, objArrCopyOf, i3 + 1, i4);
            }
            objArrCopyOf[i5] = null;
            return new f(objArr, objArrCopyOf, (i + i4) - 1, i2);
        }
        if (i2 == 0) {
            if (objArr.length == 33) {
                objArr = Arrays.copyOf(objArr, 32);
                Intrinsics.checkNotNullExpressionValue(objArr, "copyOf(...)");
            }
            return new j(objArr);
        }
        e eVar = new e(null);
        Object[] objArrG = g(objArr, i2, i - 1, eVar);
        Intrinsics.d(objArrG);
        Object obj = eVar.a;
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        Object[] objArr3 = (Object[]) obj;
        if (objArrG[1] != null) {
            return new f(objArrG, objArr3, i, i2);
        }
        Object obj2 = objArrG[0];
        Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
        return new f((Object[]) obj2, objArr3, i, i2 - 5);
    }

    public final int n() {
        return (this.d - 1) & (-32);
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List, androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.c set(int i, Object obj) {
        int i2 = this.d;
        I4.b(i, i2);
        int iN = n();
        Object[] objArr = this.b;
        Object[] objArr2 = this.c;
        int i3 = this.e;
        if (iN > i) {
            return new f(o(obj, i3, objArr, i), objArr2, i2, i3);
        }
        Object[] objArrCopyOf = Arrays.copyOf(objArr2, 32);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
        objArrCopyOf[i & 31] = obj;
        return new f(objArr, objArrCopyOf, i2, i3);
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.c y(int i) {
        I4.b(i, this.d);
        int iN = n();
        Object[] objArr = this.b;
        int i2 = this.e;
        return i >= iN ? m(objArr, iN, i2, i - iN) : m(k(objArr, i2, i, new e(this.c[0])), iN, i2, 0);
    }

    @Override // java.util.List, androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.c add(int i, Object obj) {
        int i2 = this.d;
        I4.c(i, i2);
        if (i == i2) {
            return add(obj);
        }
        int iN = n();
        Object[] objArr = this.b;
        if (i >= iN) {
            return e(obj, objArr, i - iN);
        }
        e eVar = new e(null);
        return e(eVar.a, b(objArr, this.e, i, obj, eVar), 0);
    }
}
