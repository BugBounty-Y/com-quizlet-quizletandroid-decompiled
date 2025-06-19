package androidx.collection;

import kotlin.collections.C4930v;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class C {
    public long[] a;
    public Object[] b;
    public int[] c;
    public int d;
    public int e;
    public int f;

    public C(int i) {
        this.a = S.a;
        this.b = androidx.collection.internal.a.c;
        this.c = AbstractC0215m.a;
        if (i >= 0) {
            e(S.d(i));
        } else {
            androidx.collection.internal.a.c("Capacity must be a positive value.");
            throw null;
        }
    }

    public final int a(int i) {
        int i2 = this.d;
        int i3 = i & i2;
        int i4 = 0;
        while (true) {
            long[] jArr = this.a;
            int i5 = i3 >> 3;
            int i6 = (i3 & 7) << 3;
            long j = ((jArr[i5 + 1] << (64 - i6)) & ((-i6) >> 63)) | (jArr[i5] >>> i6);
            long j2 = j & ((~j) << 7) & (-9187201950435737472L);
            if (j2 != 0) {
                return (i3 + (Long.numberOfTrailingZeros(j2) >> 3)) & i2;
            }
            i4 += 8;
            i3 = (i3 + i4) & i2;
        }
    }

    public final int b(Object obj) {
        long j;
        long j2;
        long[] jArr;
        long[] jArr2;
        int i;
        Object[] objArr;
        int i2 = 1;
        char c = 7;
        int i3 = -862048943;
        int iHashCode = (obj != null ? obj.hashCode() : 0) * (-862048943);
        int i4 = iHashCode ^ (iHashCode << 16);
        int i5 = i4 >>> 7;
        int i6 = i4 & 127;
        int i7 = this.d;
        int i8 = i5 & i7;
        int i9 = 0;
        while (true) {
            long[] jArr3 = this.a;
            int i10 = i8 >> 3;
            int i11 = (i8 & 7) << 3;
            int i12 = i2;
            char c2 = c;
            long j3 = (((-i11) >> 63) & (jArr3[i10 + i2] << (64 - i11))) | (jArr3[i10] >>> i11);
            long j4 = i6;
            int i13 = i6;
            int i14 = 0;
            long j5 = j3 ^ (j4 * 72340172838076673L);
            long j6 = -9187201950435737472L;
            long j7 = (~j5) & (j5 - 72340172838076673L) & (-9187201950435737472L);
            while (j7 != 0) {
                int iNumberOfTrailingZeros = (i8 + (Long.numberOfTrailingZeros(j7) >> 3)) & i7;
                int i15 = i3;
                if (Intrinsics.b(this.b[iNumberOfTrailingZeros], obj)) {
                    return iNumberOfTrailingZeros;
                }
                j7 &= j7 - 1;
                i3 = i15;
            }
            int i16 = i3;
            if ((j3 & ((~j3) << 6) & (-9187201950435737472L)) != 0) {
                int iA = a(i5);
                long j8 = 255;
                if (this.f != 0 || ((this.a[iA >> 3] >> ((iA & 7) << 3)) & 255) == 254) {
                    j = 255;
                    j2 = 128;
                } else {
                    int i17 = this.d;
                    if (i17 > 8) {
                        boolean z = 8;
                        j2 = 128;
                        long j9 = this.e;
                        kotlin.C c3 = kotlin.D.b;
                        if (Long.compareUnsigned(j9 * 32, i17 * 25) <= 0) {
                            long[] jArr4 = this.a;
                            int i18 = this.d;
                            Object[] objArr2 = this.b;
                            int[] iArr = this.c;
                            int i19 = (i18 + 7) >> 3;
                            int i20 = 0;
                            while (i20 < i19) {
                                long j10 = j8;
                                long j11 = jArr4[i20] & j6;
                                jArr4[i20] = (-72340172838076674L) & ((~j11) + (j11 >>> c2));
                                i20++;
                                j8 = j10;
                                j6 = -9187201950435737472L;
                            }
                            j = j8;
                            int iD = C4933y.D(jArr4);
                            int i21 = iD - 1;
                            long j12 = 72057594037927935L;
                            jArr4[i21] = (jArr4[i21] & 72057594037927935L) | (-72057594037927936L);
                            jArr4[iD] = jArr4[0];
                            int i22 = 0;
                            while (i22 != i18) {
                                int i23 = i22 >> 3;
                                int i24 = (i22 & 7) << 3;
                                long j13 = (jArr4[i23] >> i24) & j;
                                if (j13 != 128 && j13 == 254) {
                                    Object obj2 = objArr2[i22];
                                    int iHashCode2 = (obj2 != null ? obj2.hashCode() : 0) * i16;
                                    int i25 = (iHashCode2 ^ (iHashCode2 << 16)) >>> 7;
                                    int iA2 = a(i25);
                                    int i26 = i25 & i18;
                                    boolean z2 = z;
                                    long j14 = j12;
                                    if (((iA2 - i26) & i18) / 8 == ((i22 - i26) & i18) / 8) {
                                        i = i18;
                                        objArr = objArr2;
                                        jArr4[i23] = (jArr4[i23] & (~(j << i24))) | ((r9 & 127) << i24);
                                        Intrinsics.checkNotNullParameter(jArr4, "<this>");
                                        jArr4[jArr4.length - 1] = (jArr4[0] & j14) | Long.MIN_VALUE;
                                    } else {
                                        i = i18;
                                        objArr = objArr2;
                                        int i27 = iA2 >> 3;
                                        long j15 = jArr4[i27];
                                        int i28 = (iA2 & 7) << 3;
                                        if (((j15 >> i28) & j) == 128) {
                                            jArr4[i27] = (j15 & (~(j << i28))) | ((r9 & 127) << i28);
                                            jArr4[i23] = (jArr4[i23] & (~(j << i24))) | (128 << i24);
                                            objArr[iA2] = objArr[i22];
                                            objArr[i22] = null;
                                            iArr[iA2] = iArr[i22];
                                            iArr[i22] = 0;
                                        } else {
                                            jArr4[i27] = ((r9 & 127) << i28) | (j15 & (~(j << i28)));
                                            Object obj3 = objArr[iA2];
                                            objArr[iA2] = objArr[i22];
                                            objArr[i22] = obj3;
                                            int i29 = iArr[iA2];
                                            iArr[iA2] = iArr[i22];
                                            iArr[i22] = i29;
                                            i22--;
                                        }
                                        Intrinsics.checkNotNullParameter(jArr4, "<this>");
                                        jArr4[jArr4.length - 1] = (jArr4[0] & j14) | Long.MIN_VALUE;
                                    }
                                    i22++;
                                    i18 = i;
                                    objArr2 = objArr;
                                    z = z2;
                                    j12 = j14;
                                } else {
                                    i22++;
                                }
                            }
                            this.f = S.a(this.d) - this.e;
                        }
                        iA = a(i5);
                    } else {
                        j2 = 128;
                    }
                    j = 255;
                    int iB = S.b(this.d);
                    long[] jArr5 = this.a;
                    Object[] objArr3 = this.b;
                    int[] iArr2 = this.c;
                    int i30 = this.d;
                    e(iB);
                    long[] jArr6 = this.a;
                    Object[] objArr4 = this.b;
                    int[] iArr3 = this.c;
                    int i31 = this.d;
                    int i32 = 0;
                    while (i32 < i30) {
                        if (((jArr5[i32 >> 3] >> ((i32 & 7) << 3)) & 255) < j2) {
                            Object obj4 = objArr3[i32];
                            int iHashCode3 = (obj4 != null ? obj4.hashCode() : i14) * i16;
                            int i33 = iHashCode3 ^ (iHashCode3 << 16);
                            int iA3 = a(i33 >>> 7);
                            jArr = jArr6;
                            jArr2 = jArr5;
                            long j16 = i33 & 127;
                            int i34 = iA3 >> 3;
                            int i35 = (iA3 & 7) << 3;
                            long j17 = (jArr[i34] & (~(255 << i35))) | (j16 << i35);
                            jArr[i34] = j17;
                            jArr[(((iA3 - 7) & i31) + (i31 & 7)) >> 3] = j17;
                            objArr4[iA3] = obj4;
                            iArr3[iA3] = iArr2[i32];
                        } else {
                            jArr = jArr6;
                            jArr2 = jArr5;
                        }
                        i32++;
                        jArr5 = jArr2;
                        jArr6 = jArr;
                        i14 = 0;
                    }
                    iA = a(i5);
                }
                this.e++;
                int i36 = this.f;
                long[] jArr7 = this.a;
                int i37 = iA >> 3;
                long j18 = jArr7[i37];
                int i38 = (iA & 7) << 3;
                if (((j18 >> i38) & j) != j2) {
                    i12 = 0;
                }
                this.f = i36 - i12;
                int i39 = this.d;
                long j19 = (j18 & (~(j << i38))) | (j4 << i38);
                jArr7[i37] = j19;
                jArr7[(((iA - 7) & i39) + (i39 & 7)) >> 3] = j19;
                return ~iA;
            }
            i9 += 8;
            i8 = (i8 + i9) & i7;
            i2 = i12;
            c = c2;
            i6 = i13;
            i3 = i16;
        }
    }

    public final int c(Object obj) {
        int i = 0;
        int iHashCode = (obj != null ? obj.hashCode() : 0) * (-862048943);
        int i2 = iHashCode ^ (iHashCode << 16);
        int i3 = i2 & 127;
        int i4 = this.d;
        int i5 = i2 >>> 7;
        while (true) {
            int i6 = i5 & i4;
            long[] jArr = this.a;
            int i7 = i6 >> 3;
            int i8 = (i6 & 7) << 3;
            long j = ((jArr[i7 + 1] << (64 - i8)) & ((-i8) >> 63)) | (jArr[i7] >>> i8);
            long j2 = (i3 * 72340172838076673L) ^ j;
            for (long j3 = (~j2) & (j2 - 72340172838076673L) & (-9187201950435737472L); j3 != 0; j3 &= j3 - 1) {
                int iNumberOfTrailingZeros = ((Long.numberOfTrailingZeros(j3) >> 3) + i6) & i4;
                if (Intrinsics.b(this.b[iNumberOfTrailingZeros], obj)) {
                    return iNumberOfTrailingZeros;
                }
            }
            if ((j & ((~j) << 6) & (-9187201950435737472L)) != 0) {
                return -1;
            }
            i += 8;
            i5 = i6 + i;
        }
    }

    public final int d(String str) {
        int iC = c(str);
        if (iC >= 0) {
            return this.c[iC];
        }
        androidx.collection.internal.a.e("There is no key " + ((Object) str) + " in the map");
        throw null;
    }

    public final void e(int i) {
        long[] jArr;
        int iMax = i > 0 ? Math.max(7, S.c(i)) : 0;
        this.d = iMax;
        if (iMax == 0) {
            jArr = S.a;
        } else {
            jArr = new long[((iMax + 15) & (-8)) >> 3];
            C4930v.q(jArr);
        }
        this.a = jArr;
        int i2 = iMax >> 3;
        long j = 255 << ((iMax & 7) << 3);
        jArr[i2] = (jArr[i2] & (~j)) | j;
        this.f = S.a(this.d) - this.e;
        this.b = new Object[iMax];
        this.c = new int[iMax];
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x005d, code lost:
    
        return false;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean equals(java.lang.Object r19) {
        /*
            r18 = this;
            r0 = r18
            r1 = r19
            r2 = 1
            if (r1 != r0) goto L8
            return r2
        L8:
            boolean r3 = r1 instanceof androidx.collection.C
            r4 = 0
            if (r3 != 0) goto Le
            return r4
        Le:
            androidx.collection.C r1 = (androidx.collection.C) r1
            int r3 = r1.e
            int r5 = r0.e
            if (r3 == r5) goto L17
            return r4
        L17:
            java.lang.Object[] r3 = r0.b
            int[] r5 = r0.c
            long[] r6 = r0.a
            int r7 = r6.length
            int r7 = r7 + (-2)
            if (r7 < 0) goto L74
            r8 = r4
        L23:
            r9 = r6[r8]
            long r11 = ~r9
            r13 = 7
            long r11 = r11 << r13
            long r11 = r11 & r9
            r13 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r11 = r11 & r13
            int r11 = (r11 > r13 ? 1 : (r11 == r13 ? 0 : -1))
            if (r11 == 0) goto L6b
            int r11 = r8 - r7
            int r11 = ~r11
            int r11 = r11 >>> 31
            r12 = 8
            int r11 = 8 - r11
            r13 = r4
        L3d:
            if (r13 >= r11) goto L66
            r14 = 255(0xff, double:1.26E-321)
            long r14 = r14 & r9
            r16 = 128(0x80, double:6.3E-322)
            int r14 = (r14 > r16 ? 1 : (r14 == r16 ? 0 : -1))
            if (r14 >= 0) goto L5e
            int r14 = r8 << 3
            int r14 = r14 + r13
            r15 = r3[r14]
            r14 = r5[r14]
            int r15 = r1.c(r15)
            if (r15 < 0) goto L5d
            r16 = r2
            int[] r2 = r1.c
            r2 = r2[r15]
            if (r14 == r2) goto L60
        L5d:
            return r4
        L5e:
            r16 = r2
        L60:
            long r9 = r9 >> r12
            int r13 = r13 + 1
            r2 = r16
            goto L3d
        L66:
            r16 = r2
            if (r11 != r12) goto L76
            goto L6d
        L6b:
            r16 = r2
        L6d:
            if (r8 == r7) goto L76
            int r8 = r8 + 1
            r2 = r16
            goto L23
        L74:
            r16 = r2
        L76:
            return r16
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.C.equals(java.lang.Object):boolean");
    }

    public final void f(int i) {
        this.e--;
        long[] jArr = this.a;
        int i2 = this.d;
        int i3 = i >> 3;
        int i4 = (i & 7) << 3;
        long j = (jArr[i3] & (~(255 << i4))) | (254 << i4);
        jArr[i3] = j;
        jArr[(((i - 7) & i2) + (i2 & 7)) >> 3] = j;
        this.b[i] = null;
    }

    public final void g(int i, Object obj) {
        int iB = b(obj);
        if (iB < 0) {
            iB = ~iB;
        }
        this.b[iB] = obj;
        this.c[iB] = i;
    }

    public final int hashCode() {
        Object[] objArr = this.b;
        int[] iArr = this.c;
        long[] jArr = this.a;
        int length = jArr.length - 2;
        if (length < 0) {
            return 0;
        }
        int i = 0;
        int iHashCode = 0;
        while (true) {
            long j = jArr[i];
            if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                int i2 = 8 - ((~(i - length)) >>> 31);
                for (int i3 = 0; i3 < i2; i3++) {
                    if ((255 & j) < 128) {
                        int i4 = (i << 3) + i3;
                        Object obj = objArr[i4];
                        iHashCode += Integer.hashCode(iArr[i4]) ^ (obj != null ? obj.hashCode() : 0);
                    }
                    j >>= 8;
                }
                if (i2 != 8) {
                    return iHashCode;
                }
            }
            if (i == length) {
                return iHashCode;
            }
            i++;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x006a A[PHI: r8
  0x006a: PHI (r8v2 int) = (r8v1 int), (r8v3 int) binds: [B:10:0x002c, B:22:0x0068] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String toString() {
        /*
            r18 = this;
            r0 = r18
            int r1 = r0.e
            if (r1 != 0) goto L9
            java.lang.String r1 = "{}"
            return r1
        L9:
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r2 = "{"
            r1.<init>(r2)
            java.lang.Object[] r2 = r0.b
            int[] r3 = r0.c
            long[] r4 = r0.a
            int r5 = r4.length
            int r5 = r5 + (-2)
            if (r5 < 0) goto L6f
            r6 = 0
            r7 = r6
            r8 = r7
        L1e:
            r9 = r4[r7]
            long r11 = ~r9
            r13 = 7
            long r11 = r11 << r13
            long r11 = r11 & r9
            r13 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r11 = r11 & r13
            int r11 = (r11 > r13 ? 1 : (r11 == r13 ? 0 : -1))
            if (r11 == 0) goto L6a
            int r11 = r7 - r5
            int r11 = ~r11
            int r11 = r11 >>> 31
            r12 = 8
            int r11 = 8 - r11
            r13 = r6
        L38:
            if (r13 >= r11) goto L68
            r14 = 255(0xff, double:1.26E-321)
            long r14 = r14 & r9
            r16 = 128(0x80, double:6.3E-322)
            int r14 = (r14 > r16 ? 1 : (r14 == r16 ? 0 : -1))
            if (r14 >= 0) goto L64
            int r14 = r7 << 3
            int r14 = r14 + r13
            r15 = r2[r14]
            r14 = r3[r14]
            if (r15 != r0) goto L4e
            java.lang.String r15 = "(this)"
        L4e:
            r1.append(r15)
            java.lang.String r15 = "="
            r1.append(r15)
            r1.append(r14)
            int r8 = r8 + 1
            int r14 = r0.e
            if (r8 >= r14) goto L64
            java.lang.String r14 = ", "
            r1.append(r14)
        L64:
            long r9 = r9 >> r12
            int r13 = r13 + 1
            goto L38
        L68:
            if (r11 != r12) goto L6f
        L6a:
            if (r7 == r5) goto L6f
            int r7 = r7 + 1
            goto L1e
        L6f:
            r2 = 125(0x7d, float:1.75E-43)
            r1.append(r2)
            java.lang.String r1 = r1.toString()
            java.lang.String r2 = "toString(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.C.toString():java.lang.String");
    }

    public /* synthetic */ C() {
        this(6);
    }
}
