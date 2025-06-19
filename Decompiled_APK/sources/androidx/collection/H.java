package androidx.collection;

import com.j256.ormlite.stmt.query.SimpleComparison;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class H {
    public long[] a = S.a;
    public Object[] b = androidx.collection.internal.a.c;
    public long[] c = AbstractC0218p.a;
    public int d;
    public int e;
    public int f;

    public H(int i) {
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

    public final int b(Object obj) {
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

    public final long c(Object obj) {
        int iB = b(obj);
        if (iB >= 0) {
            return this.c[iB];
        }
        androidx.collection.internal.a.e("There is no key " + obj + " in the map");
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
        this.b = new Object[iMax];
        this.c = new long[iMax];
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x0077, code lost:
    
        r21 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x0082, code lost:
    
        if (((r2 & ((~r2) << 6)) & (-9187201950435737472L)) == 0) goto L69;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0084, code lost:
    
        r2 = a(r6);
        r9 = 255;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x008c, code lost:
    
        if (r40.f != 0) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x009f, code lost:
    
        if (((r40.a[r2 >> 3] >> ((r2 & 7) << 3)) & 255) != 254) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x00a1, code lost:
    
        r29 = 255;
        r24 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x00a7, code lost:
    
        r2 = r40.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x00a9, code lost:
    
        if (r2 <= 8) goto L47;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x00ab, code lost:
    
        r4 = r40.e;
        r20 = kotlin.D.b;
        r24 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x00bf, code lost:
    
        if (java.lang.Long.compareUnsigned(r4 * 32, r2 * 25) > 0) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x00c1, code lost:
    
        r2 = r40.a;
        r4 = r40.d;
        r5 = r40.b;
        r7 = r40.c;
        r8 = (r4 + 7) >> 3;
        r3 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x00d0, code lost:
    
        if (r3 >= r8) goto L73;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x00d2, code lost:
    
        r29 = r9;
        r9 = r2[r3] & r13;
        r2[r3] = (-72340172838076674L) & ((~r9) + (r9 >>> r17));
        r3 = r3 + 1;
        r9 = r29;
        r13 = -9187201950435737472L;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x00ee, code lost:
    
        r29 = r9;
        r3 = kotlin.collections.C4933y.D(r2);
        r8 = r3 - 1;
        r13 = 72057594037927935L;
        r2[r8] = (r2[r8] & 72057594037927935L) | (-72057594037927936L);
        r2[r3] = r2[0];
        r3 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0109, code lost:
    
        if (r3 == r4) goto L74;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x010b, code lost:
    
        r8 = r3 >> 3;
        r20 = (r3 & 7) << 3;
        r9 = (r2[r8] >> r20) & r29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0119, code lost:
    
        if (r9 != 128) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x011b, code lost:
    
        r3 = r3 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0120, code lost:
    
        if (r9 == 254) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0123, code lost:
    
        r9 = r5[r3];
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0125, code lost:
    
        if (r9 == null) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0127, code lost:
    
        r9 = r9.hashCode();
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x012c, code lost:
    
        r9 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x012d, code lost:
    
        r9 = r9 * r21;
        r10 = (r9 ^ (r9 << 16)) >>> 7;
        r27 = a(r10);
        r10 = r10 & r4;
        r31 = r13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x014a, code lost:
    
        if ((((r27 - r10) & r4) / 8) != (((r3 - r10) & r4) / 8)) goto L40;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x014c, code lost:
    
        r13 = r4;
        r2[r8] = (r2[r8] & (~(r29 << r20))) | ((r9 & 127) << r20);
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, "<this>");
        r2[r2.length - 1] = (r2[0] & r31) | Long.MIN_VALUE;
        r3 = r3 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x016e, code lost:
    
        r4 = r13;
        r13 = r31;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0172, code lost:
    
        r35 = r3;
        r13 = r4;
        r3 = r27 >> 3;
        r36 = r2[r3];
        r4 = (r27 & 7) << 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x0183, code lost:
    
        if (((r36 >> r4) & r29) != 128) goto L43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0185, code lost:
    
        r2[r3] = (r36 & (~(r29 << r4))) | ((r9 & 127) << r4);
        r2[r8] = (r2[r8] & (~(r29 << r20))) | (128 << r20);
        r5[r27] = r5[r35];
        r5[r35] = null;
        r7[r27] = r7[r35];
        r7[r35] = 0;
        r3 = r35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x01b1, code lost:
    
        r2[r3] = ((r9 & 127) << r4) | (r36 & (~(r29 << r4)));
        r3 = r5[r27];
        r5[r27] = r5[r35];
        r5[r35] = r3;
        r3 = r7[r27];
        r7[r27] = r7[r35];
        r7[r35] = r3;
        r3 = r35 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x01d4, code lost:
    
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, "<this>");
        r2[r2.length - 1] = (r2[0] & r31) | Long.MIN_VALUE;
        r3 = r3 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x01e5, code lost:
    
        r40.f = androidx.collection.S.a(r40.d) - r40.e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x01f2, code lost:
    
        r29 = 255;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x01f5, code lost:
    
        r24 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x01f8, code lost:
    
        r2 = androidx.collection.S.b(r40.d);
        r3 = r40.a;
        r4 = r40.b;
        r5 = r40.c;
        r7 = r40.d;
        d(r2);
        r2 = r40.a;
        r8 = r40.b;
        r9 = r40.c;
        r10 = r40.d;
        r13 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x0212, code lost:
    
        if (r13 >= r7) goto L81;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x0222, code lost:
    
        if (((r3[r13 >> 3] >> ((r13 & 7) << 3)) & 255) >= r24) goto L57;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0224, code lost:
    
        r14 = r4[r13];
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0226, code lost:
    
        if (r14 == null) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0228, code lost:
    
        r18 = r14.hashCode();
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x022d, code lost:
    
        r18 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x022f, code lost:
    
        r18 = r18 * r21;
        r18 = r18 ^ (r18 << 16);
        r15 = a(r18 >>> 7);
        r1 = r18 & 127;
        r18 = r2;
        r20 = r15 >> 3;
        r22 = (r15 & 7) << 3;
        r1 = (r18[r20] & (~(255 << r22))) | (r1 << r22);
        r18[r20] = r1;
        r18[(((r15 - 7) & r10) + (r10 & 7)) >> 3] = r1;
        r8[r15] = r14;
        r9[r15] = r5[r13];
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0268, code lost:
    
        r18 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x026a, code lost:
    
        r13 = r13 + 1;
        r2 = r18;
        r15 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x0272, code lost:
    
        r2 = a(r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x0276, code lost:
    
        r40.e++;
        r1 = r40.f;
        r3 = r40.a;
        r4 = r2 >> 3;
        r5 = r3[r4];
        r7 = (r2 & 7) << 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x028e, code lost:
    
        if (((r5 >> r7) & r29) != r24) goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x0291, code lost:
    
        r16 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x0293, code lost:
    
        r40.f = r1 - r16;
        r1 = r40.d;
        r5 = (r5 & (~(r29 << r7))) | (r11 << r7);
        r3[r4] = r5;
        r3[(((r2 - 7) & r1) + (r1 & 7)) >> 3] = r5;
        r1 = ~r2;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e(long r41, java.lang.Object r43) {
        /*
            Method dump skipped, instructions count: 713
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.H.e(long, java.lang.Object):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x005d, code lost:
    
        return false;
     */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0064  */
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
            boolean r3 = r1 instanceof androidx.collection.H
            r4 = 0
            if (r3 != 0) goto Le
            return r4
        Le:
            androidx.collection.H r1 = (androidx.collection.H) r1
            int r3 = r1.e
            int r5 = r0.e
            if (r3 == r5) goto L17
            return r4
        L17:
            java.lang.Object[] r3 = r0.b
            long[] r5 = r0.c
            long[] r6 = r0.a
            int r7 = r6.length
            int r7 = r7 + (-2)
            if (r7 < 0) goto L69
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
            if (r11 == 0) goto L64
            int r11 = r8 - r7
            int r11 = ~r11
            int r11 = r11 >>> 31
            r12 = 8
            int r11 = 8 - r11
            r13 = r4
        L3d:
            if (r13 >= r11) goto L62
            r14 = 255(0xff, double:1.26E-321)
            long r14 = r14 & r9
            r16 = 128(0x80, double:6.3E-322)
            int r14 = (r14 > r16 ? 1 : (r14 == r16 ? 0 : -1))
            if (r14 >= 0) goto L5e
            int r14 = r8 << 3
            int r14 = r14 + r13
            r15 = r3[r14]
            r16 = r5[r14]
            int r14 = r1.b(r15)
            if (r14 < 0) goto L5d
            long[] r15 = r1.c
            r14 = r15[r14]
            int r14 = (r16 > r14 ? 1 : (r16 == r14 ? 0 : -1))
            if (r14 == 0) goto L5e
        L5d:
            return r4
        L5e:
            long r9 = r9 >> r12
            int r13 = r13 + 1
            goto L3d
        L62:
            if (r11 != r12) goto L69
        L64:
            if (r8 == r7) goto L69
            int r8 = r8 + 1
            goto L23
        L69:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.H.equals(java.lang.Object):boolean");
    }

    public final int hashCode() {
        Object[] objArr = this.b;
        long[] jArr = this.c;
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
                        Object obj = objArr[i4];
                        iHashCode += (obj != null ? obj.hashCode() : 0) ^ Long.hashCode(jArr[i4]);
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
        Object[] objArr = this.b;
        long[] jArr = this.c;
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
                            Object obj = objArr[i7];
                            i2 = i3;
                            long j2 = jArr[i7];
                            if (obj == this) {
                                obj = "(this)";
                            }
                            sb.append(obj);
                            sb.append(SimpleComparison.EQUAL_TO_OPERATION);
                            sb.append(j2);
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
}
