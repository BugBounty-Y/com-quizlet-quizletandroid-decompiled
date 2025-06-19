package androidx.collection;

import com.j256.ormlite.stmt.query.SimpleComparison;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.collection.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0225x {
    public long[] a = S.a;
    public long[] b = AbstractC0218p.a;
    public int[] c = AbstractC0215m.a;
    public int d;
    public int e;
    public int f;

    public C0225x(int i) {
        if (i >= 0) {
            d(S.d(i));
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

    public final int b(long j) {
        int iHashCode = Long.hashCode(j) * (-862048943);
        int i = iHashCode ^ (iHashCode << 16);
        int i2 = i & 127;
        int i3 = this.d;
        int i4 = (i >>> 7) & i3;
        int i5 = 0;
        while (true) {
            long[] jArr = this.a;
            int i6 = i4 >> 3;
            int i7 = (i4 & 7) << 3;
            long j2 = ((jArr[i6 + 1] << (64 - i7)) & ((-i7) >> 63)) | (jArr[i6] >>> i7);
            long j3 = (i2 * 72340172838076673L) ^ j2;
            for (long j4 = (~j3) & (j3 - 72340172838076673L) & (-9187201950435737472L); j4 != 0; j4 &= j4 - 1) {
                int iNumberOfTrailingZeros = ((Long.numberOfTrailingZeros(j4) >> 3) + i4) & i3;
                if (this.b[iNumberOfTrailingZeros] == j) {
                    return iNumberOfTrailingZeros;
                }
            }
            if ((j2 & ((~j2) << 6) & (-9187201950435737472L)) != 0) {
                return -1;
            }
            i5 += 8;
            i4 = (i4 + i5) & i3;
        }
    }

    public final int c(long j) {
        int iB = b(j);
        if (iB >= 0) {
            return this.c[iB];
        }
        androidx.collection.internal.a.e("Cannot find value for key " + j);
        throw null;
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
        this.b = new long[iMax];
        this.c = new int[iMax];
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x0072, code lost:
    
        r20 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x007d, code lost:
    
        if (((r1 & ((~r1) << 6)) & (-9187201950435737472L)) == 0) goto L60;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x007f, code lost:
    
        r1 = a(r5);
        r8 = 255;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0087, code lost:
    
        if (r39.f != 0) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x009a, code lost:
    
        if (((r39.a[r1 >> 3] >> ((r1 & 7) << 3)) & 255) != 254) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x009c, code lost:
    
        r28 = 255;
        r34 = 0;
        r35 = r15;
        r23 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x00a6, code lost:
    
        r1 = r39.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x00a8, code lost:
    
        if (r1 <= 8) goto L43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x00aa, code lost:
    
        r3 = r39.e;
        r19 = kotlin.D.b;
        r23 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x00be, code lost:
    
        if (java.lang.Long.compareUnsigned(r3 * 32, r1 * 25) > 0) goto L42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x00c0, code lost:
    
        r1 = r39.a;
        r3 = r39.d;
        r4 = r39.b;
        r6 = r39.c;
        r7 = (r3 + 7) >> 3;
        r2 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x00cf, code lost:
    
        if (r2 >= r7) goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x00d1, code lost:
    
        r28 = r8;
        r8 = r1[r2] & r12;
        r1[r2] = (-72340172838076674L) & ((~r8) + (r8 >>> r16));
        r2 = r2 + r15;
        r8 = r28;
        r12 = -9187201950435737472L;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x00ec, code lost:
    
        r28 = r8;
        r2 = kotlin.collections.C4933y.D(r1);
        r7 = r2 - 1;
        r12 = 72057594037927935L;
        r1[r7] = (r1[r7] & 72057594037927935L) | (-72057594037927936L);
        r1[r2] = r1[0];
        r2 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0107, code lost:
    
        if (r2 == r3) goto L65;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0109, code lost:
    
        r7 = r2 >> 3;
        r19 = (r2 & 7) << 3;
        r8 = (r1[r7] >> r19) & r28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0117, code lost:
    
        if (r8 != 128) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0119, code lost:
    
        r2 = r2 + r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x011d, code lost:
    
        if (r8 == 254) goto L66;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0120, code lost:
    
        r8 = java.lang.Long.hashCode(r4[r2]) * r20;
        r9 = (r8 ^ (r8 << 16)) >>> 7;
        r26 = a(r9);
        r9 = r9 & r3;
        r30 = r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0143, code lost:
    
        if ((((r26 - r9) & r3) / 8) != (((r2 - r9) & r3) / 8)) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0145, code lost:
    
        r34 = r14;
        r12 = r15;
        r1[r7] = ((r8 & 127) << r19) | (r1[r7] & (~(r28 << r19)));
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, "<this>");
        r1[r1.length - r12] = (r1[r34] & r30) | Long.MIN_VALUE;
        r2 = r2 + r12;
        r15 = r12;
        r12 = r30;
        r14 = r34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x016b, code lost:
    
        r34 = r14;
        r12 = r15;
        r9 = r26 >> 3;
        r14 = r1[r9];
        r27 = (r26 & 7) << 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x017c, code lost:
    
        if (((r14 >> r27) & r28) != 128) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x017e, code lost:
    
        r35 = r12;
        r36 = "<this>";
        r38 = r2;
        r37 = r3;
        r1[r9] = ((~(r28 << r27)) & r14) | ((r8 & 127) << r27);
        r1[r7] = (r1[r7] & (~(r28 << r19))) | (128 << r19);
        r4[r26] = r4[r38];
        r4[r38] = 0;
        r6[r26] = r6[r38];
        r6[r38] = r34;
        r2 = r38;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x01ae, code lost:
    
        r38 = r2;
        r37 = r3;
        r35 = r12;
        r36 = "<this>";
        r1[r9] = ((r8 & 127) << r27) | ((~(r28 << r27)) & r14);
        r2 = r4[r26];
        r4[r26] = r4[r38];
        r4[r38] = r2;
        r2 = r6[r26];
        r6[r26] = r6[r38];
        r6[r38] = r2;
        r2 = r38 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x01d5, code lost:
    
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r36);
        r1[r1.length - 1] = (r1[r34] & r30) | Long.MIN_VALUE;
        r2 = r2 + 1;
        r12 = r30;
        r14 = r34;
        r15 = r35;
        r3 = r37;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x01ef, code lost:
    
        r34 = r14;
        r35 = r15;
        r39.f = androidx.collection.S.a(r39.d) - r39.e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0200, code lost:
    
        r28 = 255;
        r34 = 0;
        r35 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x0207, code lost:
    
        r23 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x020a, code lost:
    
        r1 = androidx.collection.S.b(r39.d);
        r2 = r39.a;
        r3 = r39.b;
        r4 = r39.c;
        r6 = r39.d;
        d(r1);
        r1 = r39.a;
        r7 = r39.b;
        r8 = r39.c;
        r9 = r39.d;
        r12 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x0225, code lost:
    
        if (r12 >= r6) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x0234, code lost:
    
        if (((r2[r12 >> 3] >> ((r12 & 7) << 3)) & 255) >= r23) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x0236, code lost:
    
        r13 = r3[r12];
        r15 = java.lang.Long.hashCode(r13) * r20;
        r15 = r15 ^ (r15 << 16);
        r17 = r1;
        r1 = a(r15 >>> 7);
        r18 = r2;
        r1 = r15 & 127;
        r15 = r1 >> 3;
        r21 = (r1 & 7) << 3;
        r1 = (r17[r15] & (~(255 << r21))) | (r1 << r21);
        r17[r15] = r1;
        r17[(((r1 - 7) & r9) + (r9 & 7)) >> 3] = r1;
        r7[r1] = r13;
        r8[r1] = r4[r12];
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x0278, code lost:
    
        r17 = r1;
        r18 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x027c, code lost:
    
        r12 = r12 + 1;
        r1 = r17;
        r2 = r18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x0283, code lost:
    
        r1 = a(r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0287, code lost:
    
        r39.e++;
        r2 = r39.f;
        r3 = r39.a;
        r4 = r1 >> 3;
        r5 = r3[r4];
        r7 = (r1 & 7) << 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x029f, code lost:
    
        if (((r5 >> r7) & r28) != r23) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x02a1, code lost:
    
        r34 = r35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x02a3, code lost:
    
        r39.f = r2 - r34;
        r2 = r39.d;
        r5 = (r5 & (~(r28 << r7))) | (r10 << r7);
        r3[r4] = r5;
        r3[(((r1 - 7) & r2) + (r2 & 7)) >> 3] = r5;
        r1 = ~r1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e(int r40, long r41) {
        /*
            Method dump skipped, instructions count: 731
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.C0225x.e(int, long):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x005e, code lost:
    
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
            boolean r3 = r1 instanceof androidx.collection.C0225x
            r4 = 0
            if (r3 != 0) goto Le
            return r4
        Le:
            androidx.collection.x r1 = (androidx.collection.C0225x) r1
            int r3 = r1.e
            int r5 = r0.e
            if (r3 == r5) goto L17
            return r4
        L17:
            long[] r3 = r0.b
            int[] r5 = r0.c
            long[] r6 = r0.a
            int r7 = r6.length
            int r7 = r7 + (-2)
            if (r7 < 0) goto L7a
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
            if (r11 == 0) goto L6f
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
            if (r14 >= 0) goto L5f
            int r14 = r8 << 3
            int r14 = r14 + r13
            r15 = r2
            r16 = r3
            r2 = r16[r14]
            r14 = r5[r14]
            int r2 = r1.b(r2)
            if (r2 < 0) goto L5e
            int[] r3 = r1.c
            r2 = r3[r2]
            if (r14 == r2) goto L62
        L5e:
            return r4
        L5f:
            r15 = r2
            r16 = r3
        L62:
            long r9 = r9 >> r12
            int r13 = r13 + 1
            r2 = r15
            r3 = r16
            goto L3d
        L69:
            r15 = r2
            r16 = r3
            if (r11 != r12) goto L7b
            goto L72
        L6f:
            r15 = r2
            r16 = r3
        L72:
            if (r8 == r7) goto L7b
            int r8 = r8 + 1
            r2 = r15
            r3 = r16
            goto L23
        L7a:
            r15 = r2
        L7b:
            return r15
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.C0225x.equals(java.lang.Object):boolean");
    }

    public final int hashCode() {
        long[] jArr = this.b;
        int[] iArr = this.c;
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
                        iHashCode += Integer.hashCode(iArr[i4]) ^ Long.hashCode(j2);
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
        int[] iArr = this.c;
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
                            int i8 = iArr[i7];
                            sb.append(j2);
                            sb.append(SimpleComparison.EQUAL_TO_OPERATION);
                            sb.append(i8);
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
                    int i9 = i3;
                    if (i5 != 8) {
                        break;
                    }
                    i = i9;
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
}
