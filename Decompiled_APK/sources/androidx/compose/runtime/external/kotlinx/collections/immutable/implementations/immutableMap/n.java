package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import androidx.compose.runtime.AbstractC0805k0;
import androidx.compose.runtime.V;
import com.google.android.gms.internal.mlkit_vision_barcode.H4;
import java.util.Arrays;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class n {
    public static final n e = new n(0, 0, new Object[0], null);
    public int a;
    public int b;
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b c;
    public Object[] d;

    public n(int i, int i2, Object[] objArr, androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b bVar) {
        this.a = i;
        this.b = i2;
        this.c = bVar;
        this.d = objArr;
    }

    public static n j(int i, Object obj, Object obj2, int i2, Object obj3, Object obj4, int i3, androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b bVar) {
        if (i3 > 30) {
            return new n(0, 0, new Object[]{obj, obj2, obj3, obj4}, bVar);
        }
        int iF = H4.f(i, i3);
        int iF2 = H4.f(i2, i3);
        if (iF != iF2) {
            return new n((1 << iF) | (1 << iF2), 0, iF < iF2 ? new Object[]{obj, obj2, obj3, obj4} : new Object[]{obj3, obj4, obj, obj2}, bVar);
        }
        return new n(0, 1 << iF, new Object[]{j(i, obj, obj2, i2, obj3, obj4, i3 + 5, bVar)}, bVar);
    }

    public final Object[] a(int i, int i2, int i3, Object obj, Object obj2, int i4, androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b bVar) {
        Object obj3 = this.d[i];
        n nVarJ = j(obj3 != null ? obj3.hashCode() : 0, obj3, x(i), i3, obj, obj2, i4 + 5, bVar);
        int iT = t(i2);
        int i5 = iT + 1;
        Object[] objArr = this.d;
        Object[] objArr2 = new Object[objArr.length - 1];
        C4930v.j(objArr, 0, objArr2, i, 6);
        C4930v.h(objArr, i, objArr2, i + 2, i5);
        objArr2[iT - 1] = nVarJ;
        C4930v.h(objArr, iT, objArr2, i5, objArr.length);
        return objArr2;
    }

    public final int b() {
        if (this.b == 0) {
            return this.d.length / 2;
        }
        int iBitCount = Integer.bitCount(this.a);
        int length = this.d.length;
        for (int i = iBitCount * 2; i < length; i++) {
            iBitCount += s(i).b();
        }
        return iBitCount;
    }

    public final boolean c(Object obj) {
        kotlin.ranges.h hVarG = kotlin.ranges.l.g(2, kotlin.ranges.l.h(0, this.d.length));
        int i = hVarG.a;
        int i2 = hVarG.b;
        int i3 = hVarG.c;
        if ((i3 > 0 && i <= i2) || (i3 < 0 && i2 <= i)) {
            while (!Intrinsics.b(obj, this.d[i])) {
                if (i != i2) {
                    i += i3;
                }
            }
            return true;
        }
        return false;
    }

    public final boolean d(int i, int i2, Object obj) {
        int iF = 1 << H4.f(i, i2);
        if (h(iF)) {
            return Intrinsics.b(obj, this.d[f(iF)]);
        }
        if (!i(iF)) {
            return false;
        }
        n nVarS = s(t(iF));
        return i2 == 30 ? nVarS.c(obj) : nVarS.d(i, i2 + 5, obj);
    }

    public final boolean e(n nVar) {
        if (this == nVar) {
            return true;
        }
        if (this.b != nVar.b || this.a != nVar.a) {
            return false;
        }
        int length = this.d.length;
        for (int i = 0; i < length; i++) {
            if (this.d[i] != nVar.d[i]) {
                return false;
            }
        }
        return true;
    }

    public final int f(int i) {
        return Integer.bitCount((i - 1) & this.a) * 2;
    }

    public final Object g(int i, int i2, Object obj) {
        int iF = 1 << H4.f(i, i2);
        if (h(iF)) {
            int iF2 = f(iF);
            if (Intrinsics.b(obj, this.d[iF2])) {
                return x(iF2);
            }
            return null;
        }
        if (!i(iF)) {
            return null;
        }
        n nVarS = s(t(iF));
        if (i2 != 30) {
            return nVarS.g(i, i2 + 5, obj);
        }
        kotlin.ranges.h hVarG = kotlin.ranges.l.g(2, kotlin.ranges.l.h(0, nVarS.d.length));
        int i3 = hVarG.a;
        int i4 = hVarG.b;
        int i5 = hVarG.c;
        if ((i5 <= 0 || i3 > i4) && (i5 >= 0 || i4 > i3)) {
            return null;
        }
        while (!Intrinsics.b(obj, nVarS.d[i3])) {
            if (i3 == i4) {
                return null;
            }
            i3 += i5;
        }
        return nVarS.x(i3);
    }

    public final boolean h(int i) {
        return (i & this.a) != 0;
    }

    public final boolean i(int i) {
        return (i & this.b) != 0;
    }

    public final n k(int i, e eVar) {
        eVar.g(eVar.f - 1);
        eVar.d = x(i);
        Object[] objArr = this.d;
        if (objArr.length == 2) {
            return null;
        }
        if (this.c != eVar.b) {
            return new n(0, 0, H4.d(i, objArr), eVar.b);
        }
        this.d = H4.d(i, objArr);
        return this;
    }

    public final n l(int i, Object obj, Object obj2, int i2, e eVar) {
        e eVar2;
        n nVarL;
        int iF = 1 << H4.f(i, i2);
        boolean zH = h(iF);
        androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b bVar = this.c;
        if (zH) {
            int iF2 = f(iF);
            if (!Intrinsics.b(obj, this.d[iF2])) {
                eVar.g(eVar.f + 1);
                androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b bVar2 = eVar.b;
                if (bVar != bVar2) {
                    return new n(this.a ^ iF, this.b | iF, a(iF2, iF, i, obj, obj2, i2, bVar2), bVar2);
                }
                this.d = a(iF2, iF, i, obj, obj2, i2, bVar2);
                this.a ^= iF;
                this.b |= iF;
                return this;
            }
            eVar.d = x(iF2);
            if (x(iF2) == obj2) {
                return this;
            }
            if (bVar == eVar.b) {
                this.d[iF2 + 1] = obj2;
                return this;
            }
            eVar.e++;
            Object[] objArr = this.d;
            Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            objArrCopyOf[iF2 + 1] = obj2;
            return new n(this.a, this.b, objArrCopyOf, eVar.b);
        }
        if (!i(iF)) {
            eVar.g(eVar.f + 1);
            androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b bVar3 = eVar.b;
            int iF3 = f(iF);
            if (bVar != bVar3) {
                return new n(this.a | iF, this.b, H4.c(this.d, iF3, obj, obj2), bVar3);
            }
            this.d = H4.c(this.d, iF3, obj, obj2);
            this.a |= iF;
            return this;
        }
        int iT = t(iF);
        n nVarS = s(iT);
        if (i2 == 30) {
            kotlin.ranges.h hVarG = kotlin.ranges.l.g(2, kotlin.ranges.l.h(0, nVarS.d.length));
            int i3 = hVarG.a;
            int i4 = hVarG.b;
            int i5 = hVarG.c;
            if ((i5 <= 0 || i3 > i4) && (i5 >= 0 || i4 > i3)) {
                eVar.g(eVar.f + 1);
                nVarL = new n(0, 0, H4.c(nVarS.d, 0, obj, obj2), eVar.b);
                eVar2 = eVar;
            } else {
                while (!Intrinsics.b(obj, nVarS.d[i3])) {
                    if (i3 == i4) {
                        eVar.g(eVar.f + 1);
                        nVarL = new n(0, 0, H4.c(nVarS.d, 0, obj, obj2), eVar.b);
                        break;
                    }
                    i3 += i5;
                }
                eVar.d = nVarS.x(i3);
                if (nVarS.c == eVar.b) {
                    nVarS.d[i3 + 1] = obj2;
                    nVarL = nVarS;
                } else {
                    eVar.e++;
                    Object[] objArr2 = nVarS.d;
                    Object[] objArrCopyOf2 = Arrays.copyOf(objArr2, objArr2.length);
                    Intrinsics.checkNotNullExpressionValue(objArrCopyOf2, "copyOf(...)");
                    objArrCopyOf2[i3 + 1] = obj2;
                    nVarL = new n(0, 0, objArrCopyOf2, eVar.b);
                }
                eVar2 = eVar;
            }
        } else {
            eVar2 = eVar;
            nVarL = nVarS.l(i, obj, obj2, i2 + 5, eVar2);
        }
        return nVarS == nVarL ? this : r(iT, nVarL, eVar2.b);
    }

    public final n m(n nVar, int i, androidx.compose.runtime.external.kotlinx.collections.immutable.internal.a aVar, e eVar) {
        Object[] objArr;
        n nVarJ;
        if (this == nVar) {
            aVar.a += b();
            return this;
        }
        int i2 = 0;
        if (i > 30) {
            androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b bVar = eVar.b;
            int i3 = nVar.b;
            Object[] objArr2 = this.d;
            Object[] objArrCopyOf = Arrays.copyOf(objArr2, objArr2.length + nVar.d.length);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            int length = this.d.length;
            kotlin.ranges.h hVarG = kotlin.ranges.l.g(2, kotlin.ranges.l.h(0, nVar.d.length));
            int i4 = hVarG.a;
            int i5 = hVarG.b;
            int i6 = hVarG.c;
            if ((i6 > 0 && i4 <= i5) || (i6 < 0 && i5 <= i4)) {
                while (true) {
                    if (c(nVar.d[i4])) {
                        aVar.a++;
                    } else {
                        Object[] objArr3 = nVar.d;
                        objArrCopyOf[length] = objArr3[i4];
                        objArrCopyOf[length + 1] = objArr3[i4 + 1];
                        length += 2;
                    }
                    if (i4 == i5) {
                        break;
                    }
                    i4 += i6;
                }
            }
            if (length != this.d.length) {
                if (length == nVar.d.length) {
                    return nVar;
                }
                if (length == objArrCopyOf.length) {
                    return new n(0, 0, objArrCopyOf, bVar);
                }
                Object[] objArrCopyOf2 = Arrays.copyOf(objArrCopyOf, length);
                Intrinsics.checkNotNullExpressionValue(objArrCopyOf2, "copyOf(...)");
                return new n(0, 0, objArrCopyOf2, bVar);
            }
        } else {
            int i7 = this.b | nVar.b;
            int i8 = this.a;
            int i9 = nVar.a;
            int i10 = (i8 ^ i9) & (~i7);
            int i11 = i8 & i9;
            int i12 = i10;
            while (i11 != 0) {
                int iLowestOneBit = Integer.lowestOneBit(i11);
                if (Intrinsics.b(this.d[f(iLowestOneBit)], nVar.d[nVar.f(iLowestOneBit)])) {
                    i12 |= iLowestOneBit;
                } else {
                    i7 |= iLowestOneBit;
                }
                i11 ^= iLowestOneBit;
            }
            if ((i7 & i12) != 0) {
                AbstractC0805k0.b("Check failed.");
            }
            n nVar2 = (Intrinsics.b(this.c, eVar.b) && this.a == i12 && this.b == i7) ? this : new n(i12, i7, new Object[Integer.bitCount(i7) + (Integer.bitCount(i12) * 2)], null);
            int i13 = i7;
            int i14 = 0;
            while (i13 != 0) {
                int iLowestOneBit2 = Integer.lowestOneBit(i13);
                Object[] objArr4 = nVar2.d;
                int length2 = (objArr4.length - 1) - i14;
                if (i(iLowestOneBit2)) {
                    nVarJ = s(t(iLowestOneBit2));
                    if (nVar.i(iLowestOneBit2)) {
                        nVarJ = nVarJ.m(nVar.s(nVar.t(iLowestOneBit2)), i + 5, aVar, eVar);
                        objArr = objArr4;
                    } else if (nVar.h(iLowestOneBit2)) {
                        int iF = nVar.f(iLowestOneBit2);
                        Object obj = nVar.d[iF];
                        Object objX = nVar.x(iF);
                        int i15 = eVar.f;
                        objArr = objArr4;
                        nVarJ = nVarJ.l(obj != null ? obj.hashCode() : i2, obj, objX, i + 5, eVar);
                        if (eVar.f == i15) {
                            aVar.a++;
                        }
                    } else {
                        objArr = objArr4;
                    }
                } else {
                    objArr = objArr4;
                    if (nVar.i(iLowestOneBit2)) {
                        n nVarS = nVar.s(nVar.t(iLowestOneBit2));
                        if (h(iLowestOneBit2)) {
                            int iF2 = f(iLowestOneBit2);
                            Object obj2 = this.d[iF2];
                            int i16 = i + 5;
                            if (nVarS.d(obj2 != null ? obj2.hashCode() : 0, i16, obj2)) {
                                aVar.a++;
                                nVarJ = nVarS;
                            } else {
                                nVarJ = nVarS.l(obj2 != null ? obj2.hashCode() : 0, obj2, x(iF2), i16, eVar);
                            }
                        } else {
                            nVarJ = nVarS;
                        }
                    } else {
                        int iF3 = f(iLowestOneBit2);
                        Object obj3 = this.d[iF3];
                        Object objX2 = x(iF3);
                        int iF4 = nVar.f(iLowestOneBit2);
                        Object obj4 = nVar.d[iF4];
                        nVarJ = j(obj3 != null ? obj3.hashCode() : 0, obj3, objX2, obj4 != null ? obj4.hashCode() : 0, obj4, nVar.x(iF4), i + 5, eVar.b);
                    }
                }
                objArr[length2] = nVarJ;
                i14++;
                i13 ^= iLowestOneBit2;
                i2 = 0;
            }
            int i17 = 0;
            while (i12 != 0) {
                int iLowestOneBit3 = Integer.lowestOneBit(i12);
                int i18 = i17 * 2;
                if (nVar.h(iLowestOneBit3)) {
                    int iF5 = nVar.f(iLowestOneBit3);
                    Object[] objArr5 = nVar2.d;
                    objArr5[i18] = nVar.d[iF5];
                    objArr5[i18 + 1] = nVar.x(iF5);
                    if (h(iLowestOneBit3)) {
                        aVar.a++;
                    }
                } else {
                    int iF6 = f(iLowestOneBit3);
                    Object[] objArr6 = nVar2.d;
                    objArr6[i18] = this.d[iF6];
                    objArr6[i18 + 1] = x(iF6);
                }
                i17++;
                i12 ^= iLowestOneBit3;
            }
            if (!e(nVar2)) {
                return nVar.e(nVar2) ? nVar : nVar2;
            }
        }
        return this;
    }

    public final n n(int i, Object obj, int i2, e eVar) {
        n nVarN;
        int iF = 1 << H4.f(i, i2);
        if (h(iF)) {
            int iF2 = f(iF);
            if (Intrinsics.b(obj, this.d[iF2])) {
                return p(iF2, iF, eVar);
            }
        } else if (i(iF)) {
            int iT = t(iF);
            n nVarS = s(iT);
            if (i2 == 30) {
                kotlin.ranges.h hVarG = kotlin.ranges.l.g(2, kotlin.ranges.l.h(0, nVarS.d.length));
                int i3 = hVarG.a;
                int i4 = hVarG.b;
                int i5 = hVarG.c;
                if ((i5 <= 0 || i3 > i4) && (i5 >= 0 || i4 > i3)) {
                    nVarN = nVarS;
                    break;
                }
                while (!Intrinsics.b(obj, nVarS.d[i3])) {
                    if (i3 == i4) {
                        nVarN = nVarS;
                        break;
                    }
                    i3 += i5;
                }
                nVarN = nVarS.k(i3, eVar);
            } else {
                nVarN = nVarS.n(i, obj, i2 + 5, eVar);
            }
            return q(nVarS, nVarN, iT, iF, eVar.b);
        }
        return this;
    }

    public final n o(int i, Object obj, Object obj2, int i2, e eVar) {
        n nVar;
        n nVarO;
        int iF = 1 << H4.f(i, i2);
        if (h(iF)) {
            int iF2 = f(iF);
            if (Intrinsics.b(obj, this.d[iF2]) && Intrinsics.b(obj2, x(iF2))) {
                return p(iF2, iF, eVar);
            }
        } else if (i(iF)) {
            int iT = t(iF);
            n nVarS = s(iT);
            if (i2 == 30) {
                kotlin.ranges.h hVarG = kotlin.ranges.l.g(2, kotlin.ranges.l.h(0, nVarS.d.length));
                int i3 = hVarG.a;
                int i4 = hVarG.b;
                int i5 = hVarG.c;
                if ((i5 <= 0 || i3 > i4) && (i5 >= 0 || i4 > i3)) {
                    nVarO = nVarS;
                    nVar = nVarS;
                } else {
                    while (true) {
                        if (!Intrinsics.b(obj, nVarS.d[i3]) || !Intrinsics.b(obj2, nVarS.x(i3))) {
                            if (i3 == i4) {
                                break;
                            }
                            i3 += i5;
                        } else {
                            nVarO = nVarS.k(i3, eVar);
                            break;
                        }
                    }
                    nVarO = nVarS;
                    nVar = nVarS;
                }
            } else {
                nVar = nVarS;
                nVarO = nVar.o(i, obj, obj2, i2 + 5, eVar);
            }
            return q(nVar, nVarO, iT, iF, eVar.b);
        }
        return this;
    }

    public final n p(int i, int i2, e eVar) {
        eVar.g(eVar.f - 1);
        eVar.d = x(i);
        Object[] objArr = this.d;
        if (objArr.length == 2) {
            return null;
        }
        if (this.c != eVar.b) {
            return new n(i2 ^ this.a, this.b, H4.d(i, objArr), eVar.b);
        }
        this.d = H4.d(i, objArr);
        this.a ^= i2;
        return this;
    }

    public final n q(n nVar, n nVar2, int i, int i2, androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b bVar) {
        androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b bVar2 = this.c;
        if (nVar2 != null) {
            return (bVar2 == bVar || nVar != nVar2) ? r(i, nVar2, bVar) : this;
        }
        Object[] objArr = this.d;
        if (objArr.length == 1) {
            return null;
        }
        if (bVar2 != bVar) {
            return new n(this.a, i2 ^ this.b, H4.e(i, objArr), bVar);
        }
        this.d = H4.e(i, objArr);
        this.b ^= i2;
        return this;
    }

    public final n r(int i, n nVar, androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b bVar) {
        Object[] objArr = this.d;
        if (objArr.length == 1 && nVar.d.length == 2 && nVar.b == 0) {
            nVar.a = this.b;
            return nVar;
        }
        if (this.c == bVar) {
            objArr[i] = nVar;
            return this;
        }
        Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
        objArrCopyOf[i] = nVar;
        return new n(this.a, this.b, objArrCopyOf, bVar);
    }

    public final n s(int i) {
        Object obj = this.d[i];
        Intrinsics.e(obj, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNode, V of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNode>");
        return (n) obj;
    }

    public final int t(int i) {
        return (this.d.length - 1) - Integer.bitCount((i - 1) & this.b);
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x00d5, code lost:
    
        if (r14 != null) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x00de, code lost:
    
        if (r14 == null) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00e1, code lost:
    
        r14.c = w(r12, r4, (androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.n) r14.c);
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00eb, code lost:
    
        return r14;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.android.billingclient.api.s u(java.lang.Object r12, int r13, java.lang.Object r14, int r15) {
        /*
            Method dump skipped, instructions count: 263
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.n.u(java.lang.Object, int, java.lang.Object, int):com.android.billingclient.api.s");
    }

    public final n v(int i, V v, int i2) {
        n nVarV;
        int iF = 1 << H4.f(i, i2);
        if (h(iF)) {
            int iF2 = f(iF);
            if (Intrinsics.b(v, this.d[iF2])) {
                Object[] objArr = this.d;
                if (objArr.length != 2) {
                    return new n(this.a ^ iF, this.b, H4.d(iF2, objArr), null);
                }
                return null;
            }
            return this;
        }
        if (i(iF)) {
            int iT = t(iF);
            n nVarS = s(iT);
            if (i2 == 30) {
                kotlin.ranges.h hVarG = kotlin.ranges.l.g(2, kotlin.ranges.l.h(0, nVarS.d.length));
                int i3 = hVarG.a;
                int i4 = hVarG.b;
                int i5 = hVarG.c;
                if ((i5 > 0 && i3 <= i4) || (i5 < 0 && i4 <= i3)) {
                    while (!Intrinsics.b(v, nVarS.d[i3])) {
                        if (i3 != i4) {
                            i3 += i5;
                        }
                    }
                    Object[] objArr2 = nVarS.d;
                    nVarV = objArr2.length == 2 ? null : new n(0, 0, H4.d(i3, objArr2), null);
                }
                nVarV = nVarS;
                break;
            }
            nVarV = nVarS.v(i, v, i2 + 5);
            if (nVarV == null) {
                Object[] objArr3 = this.d;
                if (objArr3.length != 1) {
                    return new n(this.a, iF ^ this.b, H4.e(iT, objArr3), null);
                }
                return null;
            }
            if (nVarS != nVarV) {
                return w(iT, iF, nVarV);
            }
        }
        return this;
    }

    public final n w(int i, int i2, n nVar) {
        Object[] objArr = nVar.d;
        if (objArr.length != 2 || nVar.b != 0) {
            Object[] objArr2 = this.d;
            Object[] objArrCopyOf = Arrays.copyOf(objArr2, objArr2.length);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            objArrCopyOf[i] = nVar;
            return new n(this.a, this.b, objArrCopyOf, null);
        }
        if (this.d.length == 1) {
            nVar.a = this.b;
            return nVar;
        }
        int iF = f(i2);
        Object[] objArr3 = this.d;
        Object obj = objArr[0];
        Object obj2 = objArr[1];
        Object[] objArrCopyOf2 = Arrays.copyOf(objArr3, objArr3.length + 1);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf2, "copyOf(...)");
        C4930v.h(objArrCopyOf2, i + 2, objArrCopyOf2, i + 1, objArr3.length);
        C4930v.h(objArrCopyOf2, iF + 2, objArrCopyOf2, iF, i);
        objArrCopyOf2[iF] = obj;
        objArrCopyOf2[iF + 1] = obj2;
        return new n(this.a ^ i2, i2 ^ this.b, objArrCopyOf2, null);
    }

    public final Object x(int i) {
        return this.d[i + 1];
    }
}
