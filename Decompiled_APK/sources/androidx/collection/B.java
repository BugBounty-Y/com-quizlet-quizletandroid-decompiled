package androidx.collection;

import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class B {
    public long[] a;
    public Object[] b;
    public float[] c;
    public int d;
    public int e;
    public int f;

    public B(int i) {
        this.a = S.a;
        this.b = androidx.collection.internal.a.c;
        this.c = AbstractC0211i.a;
        if (i >= 0) {
            d(S.d(i));
        } else {
            androidx.collection.internal.a.c("Capacity must be a positive value.");
            throw null;
        }
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
        C4930v.o(this.b, null, 0, this.d);
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

    public final void d(int i) {
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
        this.c = new float[iMax];
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x007b, code lost:
    
        r21 = r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x0086, code lost:
    
        if (((r2 & ((~r2) << 6)) & (-9187201950435737472L)) == 0) goto L73;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0088, code lost:
    
        r2 = b(r7);
        r8 = 255;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0090, code lost:
    
        if (r37.f != 0) goto L20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x00a4, code lost:
    
        if (((r37.a[r2 >> 3] >> ((r2 & 7) << 3)) & 255) != 254) goto L21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x00a6, code lost:
    
        r26 = 255;
        r19 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x00ac, code lost:
    
        r2 = r37.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x00ae, code lost:
    
        if (r2 <= 8) goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x00b0, code lost:
    
        r3 = r37.e;
        r10 = kotlin.D.b;
        r19 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x00c6, code lost:
    
        if (java.lang.Long.compareUnsigned(r3 * 32, r2 * 25) > 0) goto L50;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x00c8, code lost:
    
        r2 = r37.a;
        r3 = r37.d;
        r4 = r37.b;
        r5 = r37.c;
        r6 = (r3 + 7) >> 3;
        r10 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x00d5, code lost:
    
        if (r10 >= r6) goto L77;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x00d7, code lost:
    
        r26 = r8;
        r8 = r2[r10] & r13;
        r2[r10] = (-72340172838076674L) & ((~r8) + (r8 >>> r17));
        r10 = r10 + 1;
        r8 = r26;
        r13 = -9187201950435737472L;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x00f3, code lost:
    
        r26 = r8;
        r6 = kotlin.collections.C4933y.D(r2);
        r8 = r6 - 1;
        r13 = 72057594037927935L;
        r2[r8] = (r2[r8] & 72057594037927935L) | (-72057594037927936L);
        r2[r6] = r2[0];
        r6 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x010e, code lost:
    
        if (r6 == r3) goto L79;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0110, code lost:
    
        r8 = r6 >> 3;
        r24 = (r6 & 7) << 3;
        r9 = (r2[r8] >> r24) & r26;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x011e, code lost:
    
        if (r9 != 128) goto L33;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0120, code lost:
    
        r6 = r6 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0125, code lost:
    
        if (r9 == 254) goto L78;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x0128, code lost:
    
        r9 = r4[r6];
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x012a, code lost:
    
        if (r9 == null) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x012c, code lost:
    
        r9 = r9.hashCode();
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x0131, code lost:
    
        r9 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0132, code lost:
    
        r9 = r9 * r21;
        r10 = (r9 ^ (r9 << 16)) >>> 7;
        r25 = b(r10);
        r10 = r10 & r3;
        r29 = r13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x014f, code lost:
    
        if ((((r25 - r10) & r3) / 8) != (((r6 - r10) & r3) / 8)) goto L44;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0151, code lost:
    
        r13 = r3;
        r28 = r4;
        r2[r8] = (r2[r8] & (~(r26 << r24))) | ((r9 & 127) << r24);
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, "<this>");
        r2[r2.length - 1] = (r2[0] & r29) | Long.MIN_VALUE;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x0171, code lost:
    
        r6 = r6 + 1;
        r3 = r13;
        r4 = r28;
        r13 = r29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x0179, code lost:
    
        r13 = r3;
        r28 = r4;
        r3 = r25 >> 3;
        r33 = r2[r3];
        r4 = (r25 & 7) << 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x018a, code lost:
    
        if (((r33 >> r4) & r26) != 128) goto L47;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x018c, code lost:
    
        r2[r3] = (r33 & (~(r26 << r4))) | ((r9 & 127) << r4);
        r2[r8] = (r2[r8] & (~(r26 << r24))) | (128 << r24);
        r28[r25] = r28[r6];
        r28[r6] = null;
        r5[r25] = r5[r6];
        r5[r6] = 0.0f;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x01b7, code lost:
    
        r2[r3] = ((r9 & 127) << r4) | (r33 & (~(r26 << r4)));
        r3 = r28[r25];
        r28[r25] = r28[r6];
        r28[r6] = r3;
        r3 = r5[r25];
        r5[r25] = r5[r6];
        r5[r6] = r3;
        r6 = r6 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x01da, code lost:
    
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, "<this>");
        r2[r2.length - 1] = (r2[0] & r29) | Long.MIN_VALUE;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x01e9, code lost:
    
        r37.f = androidx.collection.S.a(r37.d) - r37.e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x01f6, code lost:
    
        r26 = 255;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x01f9, code lost:
    
        r19 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x01fc, code lost:
    
        r2 = androidx.collection.S.b(r37.d);
        r3 = r37.a;
        r4 = r37.b;
        r5 = r37.c;
        r6 = r37.d;
        d(r2);
        r2 = r37.a;
        r8 = r37.b;
        r9 = r37.c;
        r10 = r37.d;
        r13 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0216, code lost:
    
        if (r13 >= r6) goto L85;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x0226, code lost:
    
        if (((r3[r13 >> 3] >> ((r13 & 7) << 3)) & 255) >= r19) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0228, code lost:
    
        r14 = r4[r13];
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x022a, code lost:
    
        if (r14 == null) goto L59;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x022c, code lost:
    
        r18 = r14.hashCode();
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x0231, code lost:
    
        r18 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x0233, code lost:
    
        r18 = r18 * r21;
        r18 = r18 ^ (r18 << 16);
        r15 = b(r18 >>> 7);
        r1 = r18 & 127;
        r18 = r2;
        r23 = r15 >> 3;
        r24 = (r15 & 7) << 3;
        r1 = (r18[r23] & (~(255 << r24))) | (r1 << r24);
        r18[r23] = r1;
        r18[(((r15 - 7) & r10) + (r10 & 7)) >> 3] = r1;
        r8[r15] = r14;
        r9[r15] = r5[r13];
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x026c, code lost:
    
        r18 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x026e, code lost:
    
        r13 = r13 + 1;
        r2 = r18;
        r15 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x0276, code lost:
    
        r2 = b(r7);
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x027a, code lost:
    
        r37.e++;
        r1 = r37.f;
        r3 = r37.a;
        r4 = r2 >> 3;
        r5 = r3[r4];
        r7 = (r2 & 7) << 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x0292, code lost:
    
        if (((r5 >> r7) & r26) != r19) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x0295, code lost:
    
        r16 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x0297, code lost:
    
        r37.f = r1 - r16;
        r1 = r37.d;
        r5 = (r5 & (~(r26 << r7))) | (r11 << r7);
        r3[r4] = r5;
        r3[(((r2 - 7) & r1) + (r1 & 7)) >> 3] = r5;
        r1 = ~r2;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e(java.lang.Object r38, float r39) {
        /*
            Method dump skipped, instructions count: 719
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.B.e(java.lang.Object, float):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x0060, code lost:
    
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
            boolean r3 = r1 instanceof androidx.collection.B
            r4 = 0
            if (r3 != 0) goto Le
            return r4
        Le:
            androidx.collection.B r1 = (androidx.collection.B) r1
            int r3 = r1.e
            int r5 = r0.e
            if (r3 == r5) goto L17
            return r4
        L17:
            java.lang.Object[] r3 = r0.b
            float[] r5 = r0.c
            long[] r6 = r0.a
            int r7 = r6.length
            int r7 = r7 + (-2)
            if (r7 < 0) goto L77
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
            if (r11 == 0) goto L6e
            int r11 = r8 - r7
            int r11 = ~r11
            int r11 = r11 >>> 31
            r12 = 8
            int r11 = 8 - r11
            r13 = r4
        L3d:
            if (r13 >= r11) goto L69
            r14 = 255(0xff, double:1.26E-321)
            long r14 = r14 & r9
            r16 = 128(0x80, double:6.3E-322)
            int r14 = (r14 > r16 ? 1 : (r14 == r16 ? 0 : -1))
            if (r14 >= 0) goto L61
            int r14 = r8 << 3
            int r14 = r14 + r13
            r15 = r3[r14]
            r14 = r5[r14]
            int r15 = r1.c(r15)
            if (r15 < 0) goto L60
            r16 = r2
            float[] r2 = r1.c
            r2 = r2[r15]
            int r2 = (r14 > r2 ? 1 : (r14 == r2 ? 0 : -1))
            if (r2 != 0) goto L60
            goto L63
        L60:
            return r4
        L61:
            r16 = r2
        L63:
            long r9 = r9 >> r12
            int r13 = r13 + 1
            r2 = r16
            goto L3d
        L69:
            r16 = r2
            if (r11 != r12) goto L79
            goto L70
        L6e:
            r16 = r2
        L70:
            if (r8 == r7) goto L79
            int r8 = r8 + 1
            r2 = r16
            goto L23
        L77:
            r16 = r2
        L79:
            return r16
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.B.equals(java.lang.Object):boolean");
    }

    public final int hashCode() {
        Object[] objArr = this.b;
        float[] fArr = this.c;
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
                        iHashCode += Float.hashCode(fArr[i4]) ^ (obj != null ? obj.hashCode() : 0);
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
            float[] r3 = r0.c
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
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.B.toString():java.lang.String");
    }

    public /* synthetic */ B() {
        this(6);
    }
}
