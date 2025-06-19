package kotlinx.collections.immutable.implementations.immutableMap;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import java.util.Arrays;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j {
    public static final j e = new j(0, 0, new Object[0]);
    public int a;
    public int b;
    public final kotlinx.collections.immutable.internal.b c;
    public Object[] d;

    public j(int i, int i2, Object[] buffer, kotlinx.collections.immutable.internal.b bVar) {
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        this.a = i;
        this.b = i2;
        this.c = bVar;
        this.d = buffer;
    }

    public static j k(int i, Object obj, Object obj2, int i2, Object obj3, Object obj4, int i3, kotlinx.collections.immutable.internal.b bVar) {
        if (i3 > 30) {
            return new j(0, 0, new Object[]{obj, obj2, obj3, obj4}, bVar);
        }
        int iD = AbstractC3417z1.d(i, i3);
        int iD2 = AbstractC3417z1.d(i2, i3);
        if (iD != iD2) {
            return new j((1 << iD) | (1 << iD2), 0, iD < iD2 ? new Object[]{obj, obj2, obj3, obj4} : new Object[]{obj3, obj4, obj, obj2}, bVar);
        }
        return new j(0, 1 << iD, new Object[]{k(i, obj, obj2, i2, obj3, obj4, i3 + 5, bVar)}, bVar);
    }

    public final Object[] a(int i, int i2, int i3, Object obj, Object obj2, int i4, kotlinx.collections.immutable.internal.b bVar) {
        Object obj3 = this.d[i];
        j jVarK = k(obj3 != null ? obj3.hashCode() : 0, obj3, v(i), i3, obj, obj2, i4 + 5, bVar);
        int iT = t(i2);
        int i5 = iT + 1;
        Object[] objArr = this.d;
        Object[] objArr2 = new Object[objArr.length - 1];
        C4930v.j(objArr, 0, objArr2, i, 6);
        C4930v.h(objArr, i, objArr2, i + 2, i5);
        objArr2[iT - 1] = jVarK;
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

    public final int c(Object obj) {
        kotlin.ranges.h hVarG = kotlin.ranges.l.g(2, kotlin.ranges.l.h(0, this.d.length));
        int i = hVarG.a;
        int i2 = hVarG.b;
        int i3 = hVarG.c;
        if ((i3 <= 0 || i > i2) && (i3 >= 0 || i2 > i)) {
            return -1;
        }
        while (!Intrinsics.b(obj, this.d[i])) {
            if (i == i2) {
                return -1;
            }
            i += i3;
        }
        return i;
    }

    public final boolean d(int i, int i2, Object obj) {
        int iD = 1 << AbstractC3417z1.d(i, i2);
        if (i(iD)) {
            return Intrinsics.b(obj, this.d[f(iD)]);
        }
        if (!j(iD)) {
            return false;
        }
        j jVarS = s(t(iD));
        return i2 == 30 ? jVarS.c(obj) != -1 : jVarS.d(i, i2 + 5, obj);
    }

    public final boolean e(j jVar) {
        if (this == jVar) {
            return true;
        }
        if (this.b != jVar.b || this.a != jVar.a) {
            return false;
        }
        int length = this.d.length;
        for (int i = 0; i < length; i++) {
            if (this.d[i] != jVar.d[i]) {
                return false;
            }
        }
        return true;
    }

    public final int f(int i) {
        return Integer.bitCount((i - 1) & this.a) * 2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00ba  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean g(kotlinx.collections.immutable.implementations.immutableMap.j r8, kotlin.jvm.functions.Function2 r9) {
        /*
            r7 = this;
            java.lang.String r0 = "that"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            java.lang.String r0 = "equalityComparator"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            if (r7 != r8) goto Le
            goto Lcc
        Le:
            int r0 = r7.a
            int r1 = r8.a
            r2 = 0
            if (r0 != r1) goto Lce
            int r1 = r7.b
            int r3 = r8.b
            if (r1 == r3) goto L1d
            goto Lce
        L1d:
            r3 = 2
            if (r0 != 0) goto L72
            if (r1 != 0) goto L72
            java.lang.Object[] r0 = r7.d
            int r1 = r0.length
            java.lang.Object[] r4 = r8.d
            int r4 = r4.length
            if (r1 == r4) goto L2c
            goto Lce
        L2c:
            int r0 = r0.length
            kotlin.ranges.IntRange r0 = kotlin.ranges.l.h(r2, r0)
            kotlin.ranges.h r0 = kotlin.ranges.l.g(r3, r0)
            boolean r1 = r0 instanceof java.util.Collection
            if (r1 == 0) goto L44
            r1 = r0
            java.util.Collection r1 = (java.util.Collection) r1
            boolean r1 = r1.isEmpty()
            if (r1 == 0) goto L44
            goto Lcc
        L44:
            kotlin.ranges.i r0 = r0.iterator()
        L48:
            boolean r1 = r0.c
            if (r1 == 0) goto Lcc
            int r1 = r0.nextInt()
            java.lang.Object[] r3 = r8.d
            r3 = r3[r1]
            java.lang.Object r1 = r8.v(r1)
            int r3 = r7.c(r3)
            r4 = -1
            if (r3 == r4) goto L6e
            java.lang.Object r3 = r7.v(r3)
            java.lang.Object r1 = r9.invoke(r3, r1)
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r1 = r1.booleanValue()
            goto L6f
        L6e:
            r1 = r2
        L6f:
            if (r1 != 0) goto L48
            goto Lce
        L72:
            int r0 = java.lang.Integer.bitCount(r0)
            int r0 = r0 * r3
            kotlin.ranges.IntRange r1 = kotlin.ranges.l.h(r2, r0)
            kotlin.ranges.h r1 = kotlin.ranges.l.g(r3, r1)
            int r3 = r1.a
            int r4 = r1.b
            int r1 = r1.c
            if (r1 <= 0) goto L89
            if (r3 <= r4) goto L8d
        L89:
            if (r1 >= 0) goto Lb5
            if (r4 > r3) goto Lb5
        L8d:
            java.lang.Object[] r5 = r7.d
            r5 = r5[r3]
            java.lang.Object[] r6 = r8.d
            r6 = r6[r3]
            boolean r5 = kotlin.jvm.internal.Intrinsics.b(r5, r6)
            if (r5 != 0) goto L9c
            goto Lce
        L9c:
            java.lang.Object r5 = r7.v(r3)
            java.lang.Object r6 = r8.v(r3)
            java.lang.Object r5 = r9.invoke(r5, r6)
            java.lang.Boolean r5 = (java.lang.Boolean) r5
            boolean r5 = r5.booleanValue()
            if (r5 != 0) goto Lb1
            goto Lce
        Lb1:
            if (r3 == r4) goto Lb5
            int r3 = r3 + r1
            goto L8d
        Lb5:
            java.lang.Object[] r1 = r7.d
            int r1 = r1.length
        Lb8:
            if (r0 >= r1) goto Lcc
            kotlinx.collections.immutable.implementations.immutableMap.j r3 = r7.s(r0)
            kotlinx.collections.immutable.implementations.immutableMap.j r4 = r8.s(r0)
            boolean r3 = r3.g(r4, r9)
            if (r3 != 0) goto Lc9
            goto Lce
        Lc9:
            int r0 = r0 + 1
            goto Lb8
        Lcc:
            r8 = 1
            return r8
        Lce:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.collections.immutable.implementations.immutableMap.j.g(kotlinx.collections.immutable.implementations.immutableMap.j, kotlin.jvm.functions.Function2):boolean");
    }

    public final Object h(int i, int i2, Object obj) {
        int iD = 1 << AbstractC3417z1.d(i, i2);
        if (i(iD)) {
            int iF = f(iD);
            if (Intrinsics.b(obj, this.d[iF])) {
                return v(iF);
            }
            return null;
        }
        if (!j(iD)) {
            return null;
        }
        j jVarS = s(t(iD));
        if (i2 != 30) {
            return jVarS.h(i, i2 + 5, obj);
        }
        int iC = jVarS.c(obj);
        if (iC != -1) {
            return jVarS.v(iC);
        }
        return null;
    }

    public final boolean i(int i) {
        return (i & this.a) != 0;
    }

    public final boolean j(int i) {
        return (i & this.b) != 0;
    }

    public final j l(int i, d dVar) {
        dVar.h(dVar.f - 1);
        dVar.d = v(i);
        Object[] objArr = this.d;
        if (objArr.length == 2) {
            return null;
        }
        if (this.c != dVar.b) {
            return new j(0, 0, AbstractC3417z1.b(i, objArr), dVar.b);
        }
        this.d = AbstractC3417z1.b(i, objArr);
        return this;
    }

    public final j m(int i, Object obj, Object obj2, int i2, d mutator) {
        j jVarM;
        Intrinsics.checkNotNullParameter(mutator, "mutator");
        int iD = 1 << AbstractC3417z1.d(i, i2);
        boolean zI = i(iD);
        kotlinx.collections.immutable.internal.b bVar = this.c;
        if (zI) {
            int iF = f(iD);
            if (!Intrinsics.b(obj, this.d[iF])) {
                mutator.h(mutator.f + 1);
                kotlinx.collections.immutable.internal.b bVar2 = mutator.b;
                if (bVar != bVar2) {
                    return new j(this.a ^ iD, this.b | iD, a(iF, iD, i, obj, obj2, i2, bVar2), bVar2);
                }
                this.d = a(iF, iD, i, obj, obj2, i2, bVar2);
                this.a ^= iD;
                this.b |= iD;
                return this;
            }
            mutator.d = v(iF);
            if (v(iF) != obj2) {
                if (bVar == mutator.b) {
                    this.d[iF + 1] = obj2;
                    return this;
                }
                mutator.e++;
                Object[] objArr = this.d;
                Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length);
                Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
                objArrCopyOf[iF + 1] = obj2;
                return new j(this.a, this.b, objArrCopyOf, mutator.b);
            }
        } else {
            if (!j(iD)) {
                mutator.h(mutator.f + 1);
                kotlinx.collections.immutable.internal.b bVar3 = mutator.b;
                int iF2 = f(iD);
                if (bVar != bVar3) {
                    return new j(this.a | iD, this.b, AbstractC3417z1.a(this.d, iF2, obj, obj2), bVar3);
                }
                this.d = AbstractC3417z1.a(this.d, iF2, obj, obj2);
                this.a |= iD;
                return this;
            }
            int iT = t(iD);
            j jVarS = s(iT);
            if (i2 == 30) {
                int iC = jVarS.c(obj);
                if (iC != -1) {
                    mutator.d = jVarS.v(iC);
                    if (jVarS.c == mutator.b) {
                        jVarS.d[iC + 1] = obj2;
                        jVarM = jVarS;
                    } else {
                        mutator.e++;
                        Object[] objArr2 = jVarS.d;
                        Object[] objArrCopyOf2 = Arrays.copyOf(objArr2, objArr2.length);
                        Intrinsics.checkNotNullExpressionValue(objArrCopyOf2, "copyOf(...)");
                        objArrCopyOf2[iC + 1] = obj2;
                        jVarM = new j(0, 0, objArrCopyOf2, mutator.b);
                    }
                } else {
                    mutator.h(mutator.f + 1);
                    jVarM = new j(0, 0, AbstractC3417z1.a(jVarS.d, 0, obj, obj2), mutator.b);
                }
            } else {
                jVarM = jVarS.m(i, obj, obj2, i2 + 5, mutator);
            }
            if (jVarS != jVarM) {
                return u(iT, iD, jVarM, mutator.b);
            }
        }
        return this;
    }

    public final j n(j otherNode, int i, kotlinx.collections.immutable.internal.a intersectionCounter, d mutator) {
        Object[] objArr;
        j jVarK;
        Intrinsics.checkNotNullParameter(otherNode, "otherNode");
        Intrinsics.checkNotNullParameter(intersectionCounter, "intersectionCounter");
        Intrinsics.checkNotNullParameter(mutator, "mutator");
        if (this == otherNode) {
            intersectionCounter.a += b();
            return this;
        }
        int i2 = 0;
        if (i > 30) {
            kotlinx.collections.immutable.internal.b bVar = mutator.b;
            int i3 = otherNode.b;
            Object[] objArr2 = this.d;
            Object[] objArrCopyOf = Arrays.copyOf(objArr2, objArr2.length + otherNode.d.length);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            int length = this.d.length;
            kotlin.ranges.h hVarG = kotlin.ranges.l.g(2, kotlin.ranges.l.h(0, otherNode.d.length));
            int i4 = hVarG.a;
            int i5 = hVarG.b;
            int i6 = hVarG.c;
            if ((i6 > 0 && i4 <= i5) || (i6 < 0 && i5 <= i4)) {
                while (true) {
                    if (c(otherNode.d[i4]) != -1) {
                        intersectionCounter.a++;
                    } else {
                        Object[] objArr3 = otherNode.d;
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
                if (length == otherNode.d.length) {
                    return otherNode;
                }
                if (length == objArrCopyOf.length) {
                    return new j(0, 0, objArrCopyOf, bVar);
                }
                Object[] objArrCopyOf2 = Arrays.copyOf(objArrCopyOf, length);
                Intrinsics.checkNotNullExpressionValue(objArrCopyOf2, "copyOf(...)");
                return new j(0, 0, objArrCopyOf2, bVar);
            }
        } else {
            int i7 = this.b | otherNode.b;
            int i8 = this.a;
            int i9 = otherNode.a;
            int i10 = (i8 ^ i9) & (~i7);
            int i11 = i8 & i9;
            int i12 = i10;
            while (i11 != 0) {
                int iLowestOneBit = Integer.lowestOneBit(i11);
                if (Intrinsics.b(this.d[f(iLowestOneBit)], otherNode.d[otherNode.f(iLowestOneBit)])) {
                    i12 |= iLowestOneBit;
                } else {
                    i7 |= iLowestOneBit;
                }
                i11 ^= iLowestOneBit;
            }
            if ((i7 & i12) != 0) {
                throw new IllegalStateException("Check failed.");
            }
            j jVar = (Intrinsics.b(this.c, mutator.b) && this.a == i12 && this.b == i7) ? this : new j(i12, i7, new Object[Integer.bitCount(i7) + (Integer.bitCount(i12) * 2)]);
            int i13 = i7;
            int i14 = 0;
            while (i13 != 0) {
                int iLowestOneBit2 = Integer.lowestOneBit(i13);
                Object[] objArr4 = jVar.d;
                int length2 = (objArr4.length - 1) - i14;
                if (j(iLowestOneBit2)) {
                    jVarK = s(t(iLowestOneBit2));
                    if (otherNode.j(iLowestOneBit2)) {
                        jVarK = jVarK.n(otherNode.s(otherNode.t(iLowestOneBit2)), i + 5, intersectionCounter, mutator);
                        objArr = objArr4;
                    } else if (otherNode.i(iLowestOneBit2)) {
                        int iF = otherNode.f(iLowestOneBit2);
                        Object obj = otherNode.d[iF];
                        Object objV = otherNode.v(iF);
                        int i15 = mutator.f;
                        objArr = objArr4;
                        jVarK = jVarK.m(obj != null ? obj.hashCode() : i2, obj, objV, i + 5, mutator);
                        if (mutator.f == i15) {
                            intersectionCounter.a++;
                        }
                    } else {
                        objArr = objArr4;
                    }
                } else {
                    objArr = objArr4;
                    if (otherNode.j(iLowestOneBit2)) {
                        j jVarS = otherNode.s(otherNode.t(iLowestOneBit2));
                        if (i(iLowestOneBit2)) {
                            int iF2 = f(iLowestOneBit2);
                            Object obj2 = this.d[iF2];
                            int i16 = i + 5;
                            if (jVarS.d(obj2 != null ? obj2.hashCode() : 0, i16, obj2)) {
                                intersectionCounter.a++;
                                jVarK = jVarS;
                            } else {
                                jVarK = jVarS.m(obj2 != null ? obj2.hashCode() : 0, obj2, v(iF2), i16, mutator);
                            }
                        } else {
                            jVarK = jVarS;
                        }
                    } else {
                        int iF3 = f(iLowestOneBit2);
                        Object obj3 = this.d[iF3];
                        Object objV2 = v(iF3);
                        int iF4 = otherNode.f(iLowestOneBit2);
                        Object obj4 = otherNode.d[iF4];
                        jVarK = k(obj3 != null ? obj3.hashCode() : 0, obj3, objV2, obj4 != null ? obj4.hashCode() : 0, obj4, otherNode.v(iF4), i + 5, mutator.b);
                    }
                }
                objArr[length2] = jVarK;
                i14++;
                i13 ^= iLowestOneBit2;
                i2 = 0;
            }
            int i17 = 0;
            while (i12 != 0) {
                int iLowestOneBit3 = Integer.lowestOneBit(i12);
                int i18 = i17 * 2;
                if (otherNode.i(iLowestOneBit3)) {
                    int iF5 = otherNode.f(iLowestOneBit3);
                    Object[] objArr5 = jVar.d;
                    objArr5[i18] = otherNode.d[iF5];
                    objArr5[i18 + 1] = otherNode.v(iF5);
                    if (i(iLowestOneBit3)) {
                        intersectionCounter.a++;
                    }
                } else {
                    int iF6 = f(iLowestOneBit3);
                    Object[] objArr6 = jVar.d;
                    objArr6[i18] = this.d[iF6];
                    objArr6[i18 + 1] = v(iF6);
                }
                i17++;
                i12 ^= iLowestOneBit3;
            }
            if (!e(jVar)) {
                return otherNode.e(jVar) ? otherNode : jVar;
            }
        }
        return this;
    }

    public final j o(int i, Object obj, int i2, d mutator) {
        Intrinsics.checkNotNullParameter(mutator, "mutator");
        int iD = 1 << AbstractC3417z1.d(i, i2);
        if (i(iD)) {
            int iF = f(iD);
            if (Intrinsics.b(obj, this.d[iF])) {
                return q(iF, iD, mutator);
            }
        } else if (j(iD)) {
            int iT = t(iD);
            j jVarS = s(iT);
            if (i2 == 30) {
                int iC = jVarS.c(obj);
                if (iC != -1) {
                    jVarS = jVarS.l(iC, mutator);
                }
            } else {
                jVarS = jVarS.o(i, obj, i2 + 5, mutator);
            }
            return r(iT, iD, jVarS, mutator.b);
        }
        return this;
    }

    public final j p(int i, Object obj, Object obj2, int i2, d mutator) {
        d dVar;
        Intrinsics.checkNotNullParameter(mutator, "mutator");
        int iD = 1 << AbstractC3417z1.d(i, i2);
        if (i(iD)) {
            int iF = f(iD);
            if (Intrinsics.b(obj, this.d[iF]) && Intrinsics.b(obj2, v(iF))) {
                return q(iF, iD, mutator);
            }
        } else if (j(iD)) {
            int iT = t(iD);
            j jVarS = s(iT);
            if (i2 == 30) {
                int iC = jVarS.c(obj);
                if (iC != -1 && Intrinsics.b(obj2, jVarS.v(iC))) {
                    jVarS = jVarS.l(iC, mutator);
                }
                dVar = mutator;
            } else {
                dVar = mutator;
                jVarS = jVarS.p(i, obj, obj2, i2 + 5, dVar);
            }
            return r(iT, iD, jVarS, dVar.b);
        }
        return this;
    }

    public final j q(int i, int i2, d dVar) {
        dVar.h(dVar.f - 1);
        dVar.d = v(i);
        Object[] objArr = this.d;
        if (objArr.length == 2) {
            return null;
        }
        if (this.c != dVar.b) {
            return new j(i2 ^ this.a, this.b, AbstractC3417z1.b(i, objArr), dVar.b);
        }
        this.d = AbstractC3417z1.b(i, objArr);
        this.a ^= i2;
        return this;
    }

    public final j r(int i, int i2, j jVar, kotlinx.collections.immutable.internal.b bVar) {
        if (jVar != null) {
            return u(i, i2, jVar, bVar);
        }
        Object[] objArr = this.d;
        if (objArr.length == 1) {
            return null;
        }
        if (this.c != bVar) {
            Object[] objArr2 = new Object[objArr.length - 1];
            C4930v.j(objArr, 0, objArr2, i, 6);
            C4930v.h(objArr, i, objArr2, i + 1, objArr.length);
            return new j(this.a, i2 ^ this.b, objArr2, bVar);
        }
        Object[] objArr3 = new Object[objArr.length - 1];
        C4930v.j(objArr, 0, objArr3, i, 6);
        C4930v.h(objArr, i, objArr3, i + 1, objArr.length);
        this.d = objArr3;
        this.b ^= i2;
        return this;
    }

    public final j s(int i) {
        Object obj = this.d[i];
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of kotlinx.collections.immutable.implementations.immutableMap.TrieNode, V of kotlinx.collections.immutable.implementations.immutableMap.TrieNode>");
        return (j) obj;
    }

    public final int t(int i) {
        return (this.d.length - 1) - Integer.bitCount((i - 1) & this.b);
    }

    public final j u(int i, int i2, j jVar, kotlinx.collections.immutable.internal.b bVar) {
        Object[] objArr = jVar.d;
        if (objArr.length != 2 || jVar.b != 0) {
            if (bVar != null && this.c == bVar) {
                this.d[i] = jVar;
                return this;
            }
            Object[] objArr2 = this.d;
            Object[] objArrCopyOf = Arrays.copyOf(objArr2, objArr2.length);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            objArrCopyOf[i] = jVar;
            return new j(this.a, this.b, objArrCopyOf, bVar);
        }
        if (this.d.length == 1) {
            jVar.a = this.b;
            return jVar;
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
        return new j(this.a ^ i2, i2 ^ this.b, objArrCopyOf2, bVar);
    }

    public final Object v(int i) {
        return this.d[i + 1];
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public j(int i, int i2, Object[] buffer) {
        this(i, i2, buffer, null);
        Intrinsics.checkNotNullParameter(buffer, "buffer");
    }
}
