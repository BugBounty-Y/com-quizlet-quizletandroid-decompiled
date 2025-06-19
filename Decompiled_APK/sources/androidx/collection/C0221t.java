package androidx.collection;

import kotlin.collections.C4930v;

/* renamed from: androidx.collection.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0221t {
    public long[] a = S.a;
    public int[] b;
    public int[] c;
    public int d;
    public int e;
    public int f;

    public C0221t() {
        int[] iArr = AbstractC0215m.a;
        this.b = iArr;
        this.c = iArr;
        e(S.d(6));
    }

    public final void a() {
        this.e = 0;
        long[] jArr = this.a;
        if (jArr != S.a) {
            C4930v.q(jArr);
            long[] jArr2 = this.a;
            int i = this.d;
            int i2 = i >> 3;
            long j = 255 << ((i & 7) << 3);
            jArr2[i2] = (jArr2[i2] & (~j)) | j;
        }
        this.f = S.a(this.d) - this.e;
    }

    public final int b(int i) {
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

    public final int c(int i) {
        int iHashCode = Integer.hashCode(i) * (-862048943);
        int i2 = iHashCode ^ (iHashCode << 16);
        int i3 = i2 & 127;
        int i4 = this.d;
        int i5 = (i2 >>> 7) & i4;
        int i6 = 0;
        while (true) {
            long[] jArr = this.a;
            int i7 = i5 >> 3;
            int i8 = (i5 & 7) << 3;
            long j = ((jArr[i7 + 1] << (64 - i8)) & ((-i8) >> 63)) | (jArr[i7] >>> i8);
            long j2 = (i3 * 72340172838076673L) ^ j;
            for (long j3 = (~j2) & (j2 - 72340172838076673L) & (-9187201950435737472L); j3 != 0; j3 &= j3 - 1) {
                int iNumberOfTrailingZeros = ((Long.numberOfTrailingZeros(j3) >> 3) + i5) & i4;
                if (this.b[iNumberOfTrailingZeros] == i) {
                    return iNumberOfTrailingZeros;
                }
            }
            if ((j & ((~j) << 6) & (-9187201950435737472L)) != 0) {
                return -1;
            }
            i6 += 8;
            i5 = (i5 + i6) & i4;
        }
    }

    public final int d(int i) {
        int iC = c(i);
        if (iC >= 0) {
            return this.c[iC];
        }
        return -1;
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
        this.b = new int[iMax];
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
            boolean r3 = r1 instanceof androidx.collection.C0221t
            r4 = 0
            if (r3 != 0) goto Le
            return r4
        Le:
            androidx.collection.t r1 = (androidx.collection.C0221t) r1
            int r3 = r1.e
            int r5 = r0.e
            if (r3 == r5) goto L17
            return r4
        L17:
            int[] r3 = r0.b
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
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.C0221t.equals(java.lang.Object):boolean");
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x0073, code lost:
    
        r21 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x007e, code lost:
    
        if (((r2 & ((~r2) << 6)) & (-9187201950435737472L)) == 0) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0080, code lost:
    
        r2 = b(r6);
        r9 = 255;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0088, code lost:
    
        if (r38.f != 0) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x009b, code lost:
    
        if (((r38.a[r2 >> 3] >> ((r2 & 7) << 3)) & 255) != 254) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x009d, code lost:
    
        r27 = 255;
        r22 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x00a3, code lost:
    
        r2 = r38.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x00a5, code lost:
    
        if (r2 <= 8) goto L43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x00a7, code lost:
    
        r4 = r38.e;
        r20 = kotlin.D.b;
        r22 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x00bb, code lost:
    
        if (java.lang.Long.compareUnsigned(r4 * 32, r2 * 25) > 0) goto L42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x00bd, code lost:
    
        r2 = r38.a;
        r4 = r38.d;
        r5 = r38.b;
        r7 = r38.c;
        r8 = (r4 + 7) >> 3;
        r3 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x00cc, code lost:
    
        if (r3 >= r8) goto L65;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x00ce, code lost:
    
        r27 = r9;
        r9 = r2[r3] & r13;
        r2[r3] = (-72340172838076674L) & ((~r9) + (r9 >>> r17));
        r3 = r3 + 1;
        r9 = r27;
        r13 = -9187201950435737472L;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x00ea, code lost:
    
        r27 = r9;
        r3 = kotlin.collections.C4933y.D(r2);
        r8 = r3 - 1;
        r13 = 72057594037927935L;
        r2[r8] = (r2[r8] & 72057594037927935L) | (-72057594037927936L);
        r2[r3] = r2[0];
        r3 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0105, code lost:
    
        if (r3 == r4) goto L66;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0107, code lost:
    
        r8 = r3 >> 3;
        r20 = (r3 & 7) << 3;
        r9 = (r2[r8] >> r20) & r27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0115, code lost:
    
        if (r9 != 128) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0117, code lost:
    
        r3 = r3 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x011c, code lost:
    
        if (r9 == 254) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x011f, code lost:
    
        r9 = java.lang.Integer.hashCode(r5[r3]) * r21;
        r10 = (r9 ^ (r9 << 16)) >>> 7;
        r25 = b(r10);
        r10 = r10 & r4;
        r29 = r13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0142, code lost:
    
        if ((((r25 - r10) & r4) / 8) != (((r3 - r10) & r4) / 8)) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0144, code lost:
    
        r13 = r4;
        r2[r8] = (r2[r8] & (~(r27 << r20))) | ((r9 & 127) << r20);
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, "<this>");
        r2[r2.length - 1] = (r2[0] & r29) | Long.MIN_VALUE;
        r3 = r3 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x0166, code lost:
    
        r4 = r13;
        r13 = r29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x016a, code lost:
    
        r33 = r3;
        r13 = r4;
        r3 = r25 >> 3;
        r34 = r2[r3];
        r4 = (r25 & 7) << 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x017b, code lost:
    
        if (((r34 >> r4) & r27) != 128) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x017d, code lost:
    
        r2[r3] = (r34 & (~(r27 << r4))) | ((r9 & 127) << r4);
        r2[r8] = (r2[r8] & (~(r27 << r20))) | (128 << r20);
        r5[r25] = r5[r33];
        r5[r33] = 0;
        r7[r25] = r7[r33];
        r7[r33] = 0;
        r3 = r33;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x01a8, code lost:
    
        r2[r3] = ((r9 & 127) << r4) | (r34 & (~(r27 << r4)));
        r3 = r5[r25];
        r5[r25] = r5[r33];
        r5[r33] = r3;
        r3 = r7[r25];
        r7[r25] = r7[r33];
        r7[r33] = r3;
        r3 = r33 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x01cb, code lost:
    
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, "<this>");
        r2[r2.length - 1] = (r2[0] & r29) | Long.MIN_VALUE;
        r3 = r3 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x01dc, code lost:
    
        r38.f = androidx.collection.S.a(r38.d) - r38.e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x01e9, code lost:
    
        r27 = 255;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x01ec, code lost:
    
        r22 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x01ef, code lost:
    
        r2 = androidx.collection.S.b(r38.d);
        r3 = r38.a;
        r4 = r38.b;
        r5 = r38.c;
        r7 = r38.d;
        e(r2);
        r2 = r38.a;
        r8 = r38.b;
        r9 = r38.c;
        r10 = r38.d;
        r13 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x0209, code lost:
    
        if (r13 >= r7) goto L73;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x0219, code lost:
    
        if (((r3[r13 >> 3] >> ((r13 & 7) << 3)) & 255) >= r22) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x021b, code lost:
    
        r14 = r4[r13];
        r18 = java.lang.Integer.hashCode(r14) * r21;
        r18 = r18 ^ (r18 << 16);
        r15 = b(r18 >>> 7);
        r1 = r18 & 127;
        r18 = r2;
        r20 = r15 >> 3;
        r24 = (r15 & 7) << 3;
        r1 = (r18[r20] & (~(255 << r24))) | (r1 << r24);
        r18[r20] = r1;
        r18[(((r15 - 7) & r10) + (r10 & 7)) >> 3] = r1;
        r8[r15] = r14;
        r9[r15] = r5[r13];
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x025a, code lost:
    
        r18 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x025c, code lost:
    
        r13 = r13 + 1;
        r2 = r18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x0264, code lost:
    
        r2 = b(r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0268, code lost:
    
        r38.e++;
        r1 = r38.f;
        r3 = r38.a;
        r4 = r2 >> 3;
        r5 = r3[r4];
        r7 = (r2 & 7) << 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0280, code lost:
    
        if (((r5 >> r7) & r27) != r22) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x0283, code lost:
    
        r16 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0285, code lost:
    
        r38.f = r1 - r16;
        r1 = r38.d;
        r5 = (r5 & (~(r27 << r7))) | (r11 << r7);
        r3[r4] = r5;
        r3[(((r2 - 7) & r1) + (r1 & 7)) >> 3] = r5;
        r1 = ~r2;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f(int r39, int r40) {
        /*
            Method dump skipped, instructions count: 699
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.C0221t.f(int, int):void");
    }

    public final int hashCode() {
        int[] iArr = this.b;
        int[] iArr2 = this.c;
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
                        int i5 = iArr[i4];
                        iHashCode += Integer.hashCode(iArr2[i4]) ^ Integer.hashCode(i5);
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

    /* JADX WARN: Removed duplicated region for block: B:20:0x0066 A[PHI: r8
  0x0066: PHI (r8v2 int) = (r8v1 int), (r8v3 int) binds: [B:10:0x002c, B:19:0x0064] A[DONT_GENERATE, DONT_INLINE]] */
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
            int[] r2 = r0.b
            int[] r3 = r0.c
            long[] r4 = r0.a
            int r5 = r4.length
            int r5 = r5 + (-2)
            if (r5 < 0) goto L6b
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
            if (r11 == 0) goto L66
            int r11 = r7 - r5
            int r11 = ~r11
            int r11 = r11 >>> 31
            r12 = 8
            int r11 = 8 - r11
            r13 = r6
        L38:
            if (r13 >= r11) goto L64
            r14 = 255(0xff, double:1.26E-321)
            long r14 = r14 & r9
            r16 = 128(0x80, double:6.3E-322)
            int r14 = (r14 > r16 ? 1 : (r14 == r16 ? 0 : -1))
            if (r14 >= 0) goto L60
            int r14 = r7 << 3
            int r14 = r14 + r13
            r15 = r2[r14]
            r14 = r3[r14]
            r1.append(r15)
            java.lang.String r15 = "="
            r1.append(r15)
            r1.append(r14)
            int r8 = r8 + 1
            int r14 = r0.e
            if (r8 >= r14) goto L60
            java.lang.String r14 = ", "
            r1.append(r14)
        L60:
            long r9 = r9 >> r12
            int r13 = r13 + 1
            goto L38
        L64:
            if (r11 != r12) goto L6b
        L66:
            if (r7 == r5) goto L6b
            int r7 = r7 + 1
            goto L1e
        L6b:
            r2 = 125(0x7d, float:1.75E-43)
            r1.append(r2)
            java.lang.String r1 = r1.toString()
            java.lang.String r2 = "toString(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.C0221t.toString():java.lang.String");
    }
}
