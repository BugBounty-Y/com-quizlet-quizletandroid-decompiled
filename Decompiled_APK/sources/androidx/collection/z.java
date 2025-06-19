package androidx.collection;

import com.j256.ormlite.stmt.query.SimpleComparison;
import kotlin.collections.C4930v;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class z {
    public long[] a;
    public long[] b;
    public Object[] c;
    public int d;
    public int e;
    public int f;

    public z(int i) {
        this.a = S.a;
        this.b = AbstractC0218p.a;
        this.c = androidx.collection.internal.a.c;
        if (i >= 0) {
            e(S.d(i));
        } else {
            androidx.collection.internal.a.c("Capacity must be a positive value.");
            throw null;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0066, code lost:
    
        if (((r6 & ((~r6) << 6)) & (-9187201950435737472L)) == 0) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0068, code lost:
    
        r10 = -1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean a(long r18) {
        /*
            r17 = this;
            r0 = r17
            int r1 = java.lang.Long.hashCode(r18)
            r2 = -862048943(0xffffffffcc9e2d51, float:-8.293031E7)
            int r1 = r1 * r2
            int r2 = r1 << 16
            r1 = r1 ^ r2
            r2 = r1 & 127(0x7f, float:1.78E-43)
            int r3 = r0.d
            int r1 = r1 >>> 7
            r1 = r1 & r3
            r4 = 0
            r5 = r4
        L16:
            long[] r6 = r0.a
            int r7 = r1 >> 3
            r8 = r1 & 7
            int r8 = r8 << 3
            r9 = r6[r7]
            long r9 = r9 >>> r8
            r11 = 1
            int r7 = r7 + r11
            r12 = r6[r7]
            int r6 = 64 - r8
            long r6 = r12 << r6
            long r12 = (long) r8
            long r12 = -r12
            r8 = 63
            long r12 = r12 >> r8
            long r6 = r6 & r12
            long r6 = r6 | r9
            long r8 = (long) r2
            r12 = 72340172838076673(0x101010101010101, double:7.748604185489348E-304)
            long r8 = r8 * r12
            long r8 = r8 ^ r6
            long r12 = r8 - r12
            long r8 = ~r8
            long r8 = r8 & r12
            r12 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r8 = r8 & r12
        L42:
            r14 = 0
            int r10 = (r8 > r14 ? 1 : (r8 == r14 ? 0 : -1))
            if (r10 == 0) goto L5f
            int r10 = java.lang.Long.numberOfTrailingZeros(r8)
            int r10 = r10 >> 3
            int r10 = r10 + r1
            r10 = r10 & r3
            long[] r14 = r0.b
            r15 = r14[r10]
            int r14 = (r15 > r18 ? 1 : (r15 == r18 ? 0 : -1))
            if (r14 != 0) goto L59
            goto L69
        L59:
            r14 = 1
            long r14 = r8 - r14
            long r8 = r8 & r14
            goto L42
        L5f:
            long r8 = ~r6
            r10 = 6
            long r8 = r8 << r10
            long r6 = r6 & r8
            long r6 = r6 & r12
            int r6 = (r6 > r14 ? 1 : (r6 == r14 ? 0 : -1))
            if (r6 == 0) goto L6d
            r10 = -1
        L69:
            if (r10 < 0) goto L6c
            return r11
        L6c:
            return r4
        L6d:
            int r5 = r5 + 8
            int r1 = r1 + r5
            r1 = r1 & r3
            goto L16
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.z.a(long):boolean");
    }

    public final int b(long j) {
        long j2;
        int i;
        long j3;
        long[] jArr;
        long[] jArr2;
        int i2;
        int i3;
        String str;
        int i4;
        int i5 = 1;
        int i6 = -862048943;
        int iHashCode = Long.hashCode(j) * (-862048943);
        int i7 = iHashCode ^ (iHashCode << 16);
        char c = 7;
        int i8 = i7 >>> 7;
        int i9 = i7 & 127;
        int i10 = this.d;
        int i11 = i8 & i10;
        int i12 = 0;
        while (true) {
            long[] jArr3 = this.a;
            int i13 = i11 >> 3;
            int i14 = (i11 & 7) << 3;
            int i15 = i6;
            char c2 = c;
            long j4 = (((-i14) >> 63) & (jArr3[i13 + i5] << (64 - i14))) | (jArr3[i13] >>> i14);
            long j5 = i9;
            int i16 = i5;
            int i17 = i9;
            long j6 = j4 ^ (j5 * 72340172838076673L);
            long j7 = -9187201950435737472L;
            for (long j8 = (~j6) & (j6 - 72340172838076673L) & (-9187201950435737472L); j8 != 0; j8 &= j8 - 1) {
                int iNumberOfTrailingZeros = (i11 + (Long.numberOfTrailingZeros(j8) >> 3)) & i10;
                if (this.b[iNumberOfTrailingZeros] == j) {
                    return iNumberOfTrailingZeros;
                }
            }
            if ((((~j4) << 6) & j4 & (-9187201950435737472L)) != 0) {
                int iC = c(i8);
                long j9 = 255;
                if (this.f != 0 || ((this.a[iC >> 3] >> ((iC & 7) << 3)) & 255) == 254) {
                    j2 = 255;
                    i = i16;
                    j3 = 128;
                } else {
                    int i18 = this.d;
                    if (i18 > 8) {
                        long j10 = this.e;
                        kotlin.C c3 = kotlin.D.b;
                        j3 = 128;
                        if (Long.compareUnsigned(j10 * 32, i18 * 25) <= 0) {
                            long[] jArr4 = this.a;
                            int i19 = this.d;
                            long[] jArr5 = this.b;
                            Object[] objArr = this.c;
                            int i20 = (i19 + 7) >> 3;
                            int i21 = 0;
                            while (i21 < i20) {
                                long j11 = j9;
                                long j12 = jArr4[i21] & j7;
                                jArr4[i21] = (-72340172838076674L) & ((~j12) + (j12 >>> c2));
                                i21 += i16;
                                j9 = j11;
                                j7 = -9187201950435737472L;
                            }
                            j2 = j9;
                            int iD = C4933y.D(jArr4);
                            int i22 = iD - 1;
                            long j13 = 72057594037927935L;
                            jArr4[i22] = (jArr4[i22] & 72057594037927935L) | (-72057594037927936L);
                            jArr4[iD] = jArr4[0];
                            int i23 = 0;
                            while (i23 != i19) {
                                int i24 = i23 >> 3;
                                int i25 = (i23 & 7) << 3;
                                long j14 = (jArr4[i24] >> i25) & j2;
                                if (j14 != 128 && j14 == 254) {
                                    int iHashCode2 = Long.hashCode(jArr5[i23]) * i15;
                                    int i26 = (iHashCode2 ^ (iHashCode2 << 16)) >>> 7;
                                    int iC2 = c(i26);
                                    int i27 = i26 & i19;
                                    long j15 = j13;
                                    if (((iC2 - i27) & i19) / 8 == ((i23 - i27) & i19) / 8) {
                                        jArr4[i24] = ((r8 & 127) << i25) | (jArr4[i24] & (~(j2 << i25)));
                                        Intrinsics.checkNotNullParameter(jArr4, "<this>");
                                        jArr4[jArr4.length - 1] = (jArr4[0] & j15) | Long.MIN_VALUE;
                                        i23++;
                                        i15 = i15;
                                        j13 = j15;
                                        i16 = i16;
                                    } else {
                                        int i28 = i16;
                                        int i29 = i15;
                                        int i30 = iC2 >> 3;
                                        long j16 = jArr4[i30];
                                        int i31 = (iC2 & 7) << 3;
                                        if (((j16 >> i31) & j2) == 128) {
                                            i3 = i29;
                                            str = "<this>";
                                            int i32 = i23;
                                            i2 = i19;
                                            jArr4[i30] = ((~(j2 << i31)) & j16) | ((r8 & 127) << i31);
                                            jArr4[i24] = (jArr4[i24] & (~(j2 << i25))) | (128 << i25);
                                            jArr5[iC2] = jArr5[i32];
                                            jArr5[i32] = 0;
                                            objArr[iC2] = objArr[i32];
                                            objArr[i32] = null;
                                            i4 = i32;
                                        } else {
                                            int i33 = i23;
                                            i2 = i19;
                                            i3 = i29;
                                            str = "<this>";
                                            jArr4[i30] = ((r8 & 127) << i31) | ((~(j2 << i31)) & j16);
                                            long j17 = jArr5[iC2];
                                            jArr5[iC2] = jArr5[i33];
                                            jArr5[i33] = j17;
                                            Object obj = objArr[iC2];
                                            objArr[iC2] = objArr[i33];
                                            objArr[i33] = obj;
                                            i4 = i33 - 1;
                                        }
                                        Intrinsics.checkNotNullParameter(jArr4, str);
                                        jArr4[jArr4.length - 1] = (jArr4[0] & j15) | Long.MIN_VALUE;
                                        i23 = i4 + 1;
                                        j13 = j15;
                                        i16 = i28;
                                        i15 = i3;
                                        i19 = i2;
                                    }
                                } else {
                                    i23 += i16;
                                }
                            }
                            i = i16;
                            this.f = S.a(this.d) - this.e;
                        }
                        iC = c(i8);
                    } else {
                        j3 = 128;
                    }
                    j2 = 255;
                    i = i16;
                    int iB = S.b(this.d);
                    long[] jArr6 = this.a;
                    long[] jArr7 = this.b;
                    Object[] objArr2 = this.c;
                    int i34 = this.d;
                    e(iB);
                    long[] jArr8 = this.a;
                    long[] jArr9 = this.b;
                    Object[] objArr3 = this.c;
                    int i35 = this.d;
                    int i36 = 0;
                    while (i36 < i34) {
                        if (((jArr6[i36 >> 3] >> ((i36 & 7) << 3)) & 255) < j3) {
                            long j18 = jArr7[i36];
                            int iHashCode3 = Long.hashCode(j18) * i15;
                            int i37 = iHashCode3 ^ (iHashCode3 << 16);
                            jArr = jArr8;
                            int iC3 = c(i37 >>> 7);
                            jArr2 = jArr6;
                            long j19 = i37 & 127;
                            int i38 = iC3 >> 3;
                            int i39 = (iC3 & 7) << 3;
                            long j20 = (jArr[i38] & (~(255 << i39))) | (j19 << i39);
                            jArr[i38] = j20;
                            jArr[(((iC3 - 7) & i35) + (i35 & 7)) >> 3] = j20;
                            jArr9[iC3] = j18;
                            objArr3[iC3] = objArr2[i36];
                        } else {
                            jArr = jArr8;
                            jArr2 = jArr6;
                        }
                        i36++;
                        jArr8 = jArr;
                        jArr6 = jArr2;
                    }
                    iC = c(i8);
                }
                this.e++;
                int i40 = this.f;
                long[] jArr10 = this.a;
                int i41 = iC >> 3;
                long j21 = jArr10[i41];
                int i42 = (iC & 7) << 3;
                if (((j21 >> i42) & j2) != j3) {
                    i = 0;
                }
                this.f = i40 - i;
                int i43 = this.d;
                long j22 = (j21 & (~(j2 << i42))) | (j5 << i42);
                jArr10[i41] = j22;
                jArr10[(((iC - 7) & i43) + (i43 & 7)) >> 3] = j22;
                return iC;
            }
            i12 += 8;
            i11 = (i11 + i12) & i10;
            c = c2;
            i9 = i17;
            i5 = i16;
            i6 = i15;
        }
    }

    public final int c(int i) {
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

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0063, code lost:
    
        if (((r4 & ((~r4) << 6)) & (-9187201950435737472L)) == 0) goto L18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0065, code lost:
    
        r10 = -1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(long r15) {
        /*
            r14 = this;
            int r0 = java.lang.Long.hashCode(r15)
            r1 = -862048943(0xffffffffcc9e2d51, float:-8.293031E7)
            int r0 = r0 * r1
            int r1 = r0 << 16
            r0 = r0 ^ r1
            r1 = r0 & 127(0x7f, float:1.78E-43)
            int r2 = r14.d
            int r0 = r0 >>> 7
            r0 = r0 & r2
            r3 = 0
        L13:
            long[] r4 = r14.a
            int r5 = r0 >> 3
            r6 = r0 & 7
            int r6 = r6 << 3
            r7 = r4[r5]
            long r7 = r7 >>> r6
            int r5 = r5 + 1
            r9 = r4[r5]
            int r4 = 64 - r6
            long r4 = r9 << r4
            long r9 = (long) r6
            long r9 = -r9
            r6 = 63
            long r9 = r9 >> r6
            long r4 = r4 & r9
            long r4 = r4 | r7
            long r6 = (long) r1
            r8 = 72340172838076673(0x101010101010101, double:7.748604185489348E-304)
            long r6 = r6 * r8
            long r6 = r6 ^ r4
            long r8 = r6 - r8
            long r6 = ~r6
            long r6 = r6 & r8
            r8 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r6 = r6 & r8
        L3f:
            r10 = 0
            int r12 = (r6 > r10 ? 1 : (r6 == r10 ? 0 : -1))
            if (r12 == 0) goto L5c
            int r10 = java.lang.Long.numberOfTrailingZeros(r6)
            int r10 = r10 >> 3
            int r10 = r10 + r0
            r10 = r10 & r2
            long[] r11 = r14.b
            r12 = r11[r10]
            int r11 = (r12 > r15 ? 1 : (r12 == r15 ? 0 : -1))
            if (r11 != 0) goto L56
            goto L66
        L56:
            r10 = 1
            long r10 = r6 - r10
            long r6 = r6 & r10
            goto L3f
        L5c:
            long r6 = ~r4
            r12 = 6
            long r6 = r6 << r12
            long r4 = r4 & r6
            long r4 = r4 & r8
            int r4 = (r4 > r10 ? 1 : (r4 == r10 ? 0 : -1))
            if (r4 == 0) goto L6f
            r10 = -1
        L66:
            if (r10 < 0) goto L6d
            java.lang.Object[] r0 = r14.c
            r0 = r0[r10]
            return r0
        L6d:
            r0 = 0
            return r0
        L6f:
            int r3 = r3 + 8
            int r0 = r0 + r3
            r0 = r0 & r2
            goto L13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.z.d(long):java.lang.Object");
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
        this.b = new long[iMax];
        this.c = new Object[iMax];
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x0060, code lost:
    
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
            boolean r3 = r1 instanceof androidx.collection.z
            r4 = 0
            if (r3 != 0) goto Le
            return r4
        Le:
            androidx.collection.z r1 = (androidx.collection.z) r1
            int r3 = r1.e
            int r5 = r0.e
            if (r3 == r5) goto L17
            return r4
        L17:
            long[] r3 = r0.b
            java.lang.Object[] r5 = r0.c
            long[] r6 = r0.a
            int r7 = r6.length
            int r7 = r7 + (-2)
            if (r7 < 0) goto L87
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
            if (r11 == 0) goto L7c
            int r11 = r8 - r7
            int r11 = ~r11
            int r11 = r11 >>> 31
            r12 = 8
            int r11 = 8 - r11
            r13 = r4
        L3d:
            if (r13 >= r11) goto L76
            r14 = 255(0xff, double:1.26E-321)
            long r14 = r14 & r9
            r16 = 128(0x80, double:6.3E-322)
            int r14 = (r14 > r16 ? 1 : (r14 == r16 ? 0 : -1))
            if (r14 >= 0) goto L6c
            int r14 = r8 << 3
            int r14 = r14 + r13
            r15 = r2
            r16 = r3
            r2 = r16[r14]
            r14 = r5[r14]
            if (r14 != 0) goto L61
            java.lang.Object r14 = r1.d(r2)
            if (r14 != 0) goto L60
            boolean r2 = r1.a(r2)
            if (r2 != 0) goto L6f
        L60:
            return r4
        L61:
            java.lang.Object r2 = r1.d(r2)
            boolean r2 = r14.equals(r2)
            if (r2 != 0) goto L6f
            return r4
        L6c:
            r15 = r2
            r16 = r3
        L6f:
            long r9 = r9 >> r12
            int r13 = r13 + 1
            r2 = r15
            r3 = r16
            goto L3d
        L76:
            r15 = r2
            r16 = r3
            if (r11 != r12) goto L88
            goto L7f
        L7c:
            r15 = r2
            r16 = r3
        L7f:
            if (r8 == r7) goto L88
            int r8 = r8 + 1
            r2 = r15
            r3 = r16
            goto L23
        L87:
            r15 = r2
        L88:
            return r15
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.z.equals(java.lang.Object):boolean");
    }

    public final void f(long j, Object obj) {
        int iB = b(j);
        this.b[iB] = j;
        this.c[iB] = obj;
    }

    public final int hashCode() {
        long[] jArr = this.b;
        Object[] objArr = this.c;
        long[] jArr2 = this.a;
        int length = jArr2.length - 2;
        if (length < 0) {
            return 0;
        }
        int i = 0;
        int iHashCode = 0;
        while (true) {
            long j = jArr2[i];
            if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                int i2 = 8 - ((~(i - length)) >>> 31);
                for (int i3 = 0; i3 < i2; i3++) {
                    if ((255 & j) < 128) {
                        int i4 = (i << 3) + i3;
                        long j2 = jArr[i4];
                        Object obj = objArr[i4];
                        iHashCode += (obj != null ? obj.hashCode() : 0) ^ Long.hashCode(j2);
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

    public final String toString() {
        int i;
        int i2;
        if (this.e == 0) {
            return "{}";
        }
        StringBuilder sb = new StringBuilder("{");
        long[] jArr = this.b;
        Object[] objArr = this.c;
        long[] jArr2 = this.a;
        int length = jArr2.length - 2;
        if (length >= 0) {
            int i3 = 0;
            int i4 = 0;
            while (true) {
                long j = jArr2[i3];
                if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                    int i5 = 8 - ((~(i3 - length)) >>> 31);
                    int i6 = 0;
                    while (i6 < i5) {
                        if ((255 & j) < 128) {
                            int i7 = (i3 << 3) + i6;
                            i2 = i3;
                            long j2 = jArr[i7];
                            Object obj = objArr[i7];
                            sb.append(j2);
                            sb.append(SimpleComparison.EQUAL_TO_OPERATION);
                            if (obj == this) {
                                obj = "(this)";
                            }
                            sb.append(obj);
                            i4++;
                            if (i4 < this.e) {
                                sb.append(", ");
                            }
                        } else {
                            i2 = i3;
                        }
                        j >>= 8;
                        i6++;
                        i3 = i2;
                    }
                    int i8 = i3;
                    if (i5 != 8) {
                        break;
                    }
                    i = i8;
                } else {
                    i = i3;
                }
                if (i == length) {
                    break;
                }
                i3 = i + 1;
            }
        }
        sb.append('}');
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public /* synthetic */ z() {
        this(6);
    }
}
