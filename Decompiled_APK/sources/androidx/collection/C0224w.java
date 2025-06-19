package androidx.collection;

import kotlin.collections.C4930v;

/* renamed from: androidx.collection.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0224w {
    public long[] a;
    public int[] b;
    public int c;
    public int d;
    public int e;

    public C0224w(int i) {
        this.a = S.a;
        this.b = AbstractC0215m.a;
        if (i >= 0) {
            e(S.d(i));
        } else {
            androidx.collection.internal.a.c("Capacity must be a positive value.");
            throw null;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x0074, code lost:
    
        r22 = r6;
        r3 = '\b';
     */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x007f, code lost:
    
        if (((r2 & ((~r2) << 6)) & (-9187201950435737472L)) == 0) goto L62;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0081, code lost:
    
        r2 = d(r7);
        r10 = 255;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0089, code lost:
    
        if (r38.e != 0) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x009c, code lost:
    
        if (((r38.a[r2 >> 3] >> ((r2 & 7) << 3)) & 255) != 254) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x009e, code lost:
    
        r27 = 255;
        r23 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x00a4, code lost:
    
        r2 = r38.c;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x00a6, code lost:
    
        if (r2 <= 8) goto L43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x00a8, code lost:
    
        r5 = r38.d;
        r21 = kotlin.D.b;
        r23 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x00bc, code lost:
    
        if (java.lang.Long.compareUnsigned(r5 * 32, r2 * 25) > 0) goto L42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x00be, code lost:
    
        r2 = r38.a;
        r5 = r38.c;
        r6 = r38.b;
        r8 = (r5 + 7) >> 3;
        r9 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x00ca, code lost:
    
        if (r9 >= r8) goto L66;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x00cc, code lost:
    
        r27 = r10;
        r10 = r2[r9] & r14;
        r2[r9] = (-72340172838076674L) & ((~r10) + (r10 >>> r18));
        r9 = r9 + 1;
        r10 = r27;
        r14 = -9187201950435737472L;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x00e8, code lost:
    
        r27 = r10;
        r8 = kotlin.collections.C4933y.D(r2);
        r9 = r8 - 1;
        r14 = 72057594037927935L;
        r2[r9] = (r2[r9] & 72057594037927935L) | (-72057594037927936L);
        r2[r8] = r2[0];
        r8 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0104, code lost:
    
        if (r8 == r5) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0106, code lost:
    
        r9 = r8 >> 3;
        r21 = (r8 & 7) << 3;
        r10 = (r2[r9] >> r21) & r27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0114, code lost:
    
        if (r10 != 128) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0116, code lost:
    
        r8 = r8 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x011b, code lost:
    
        if (r10 == 254) goto L68;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x011e, code lost:
    
        r10 = java.lang.Integer.hashCode(r6[r8]) * r22;
        r11 = (r10 ^ (r10 << 16)) >>> 7;
        r25 = d(r11);
        r11 = r11 & r5;
        r29 = r3;
        r32 = r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0143, code lost:
    
        if ((((r25 - r11) & r5) / 8) != (((r8 - r11) & r5) / 8)) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0145, code lost:
    
        r3 = r5;
        r15 = r6;
        r2[r9] = (r2[r9] & (~(r27 << r21))) | ((r10 & 127) << r21);
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, "<this>");
        r2[r2.length - 1] = (r2[0] & r32) | Long.MIN_VALUE;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x0164, code lost:
    
        r8 = r8 + 1;
        r5 = r3;
        r6 = r15;
        r3 = r29;
        r14 = r32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x016d, code lost:
    
        r3 = r5;
        r15 = r6;
        r5 = r25 >> 3;
        r34 = r2[r5];
        r6 = (r25 & 7) << 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x017d, code lost:
    
        if (((r34 >> r6) & r27) != 128) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x017f, code lost:
    
        r2[r5] = (r34 & (~(r27 << r6))) | ((r10 & 127) << r6);
        r2[r9] = (r2[r9] & (~(r27 << r21))) | (128 << r21);
        r15[r25] = r15[r8];
        r15[r8] = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x01a2, code lost:
    
        r2[r5] = ((r10 & 127) << r6) | (r34 & (~(r27 << r6)));
        r5 = r15[r25];
        r15[r25] = r15[r8];
        r15[r8] = r5;
        r8 = r8 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x01bd, code lost:
    
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, "<this>");
        r2[r2.length - 1] = (r2[0] & r32) | Long.MIN_VALUE;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x01cc, code lost:
    
        r38.e = androidx.collection.S.a(r38.c) - r38.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x01d9, code lost:
    
        r27 = 255;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x01dc, code lost:
    
        r23 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x01df, code lost:
    
        r2 = androidx.collection.S.b(r38.c);
        r3 = r38.a;
        r5 = r38.b;
        r6 = r38.c;
        e(r2);
        r2 = r38.a;
        r8 = r38.b;
        r9 = r38.c;
        r10 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x01f6, code lost:
    
        if (r10 >= r6) goto L74;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x0205, code lost:
    
        if (((r3[r10 >> 3] >> ((r10 & 7) << 3)) & 255) >= r23) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x0207, code lost:
    
        r11 = r5[r10];
        r14 = java.lang.Integer.hashCode(r11) * r22;
        r14 = r14 ^ (r14 << 16);
        r15 = d(r14 >>> 7);
        r19 = r2;
        r1 = r14 & 127;
        r14 = r15 >> 3;
        r20 = (r15 & 7) << 3;
        r1 = (r19[r14] & (~(255 << r20))) | (r1 << r20);
        r19[r14] = r1;
        r19[(((r15 - 7) & r9) + (r9 & 7)) >> 3] = r1;
        r8[r15] = r11;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x0240, code lost:
    
        r19 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x0242, code lost:
    
        r10 = r10 + 1;
        r2 = r19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x0249, code lost:
    
        r19 = d(r7);
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0250, code lost:
    
        r19 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0252, code lost:
    
        r38.d++;
        r1 = r38.e;
        r2 = r38.a;
        r3 = r19 >> 3;
        r5 = r2[r3];
        r7 = (r19 & 7) << 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x026a, code lost:
    
        if (((r5 >> r7) & r27) != r23) goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x026c, code lost:
    
        r8 = r17 ? 1 : 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x026f, code lost:
    
        r8 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0271, code lost:
    
        r38.e = r1 - r8;
        r1 = r38.c;
        r5 = (r5 & (~(r27 << r7))) | (r12 << r7);
        r2[r3] = r5;
        r2[(((r19 - 7) & r1) + (r1 & 7)) >> 3] = r5;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean a(int r39) {
        /*
            Method dump skipped, instructions count: 675
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.C0224w.a(int):boolean");
    }

    public final void b() {
        this.d = 0;
        long[] jArr = this.a;
        if (jArr != S.a) {
            C4930v.q(jArr);
            long[] jArr2 = this.a;
            int i = this.c;
            int i2 = i >> 3;
            long j = 255 << ((i & 7) << 3);
            jArr2[i2] = (jArr2[i2] & (~j)) | j;
        }
        this.e = S.a(this.c) - this.d;
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0067, code lost:
    
        if (((r6 & ((~r6) << 6)) & (-9187201950435737472L)) == 0) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0069, code lost:
    
        r10 = -1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean c(int r19) {
        /*
            r18 = this;
            r0 = r18
            int r1 = java.lang.Integer.hashCode(r19)
            r2 = -862048943(0xffffffffcc9e2d51, float:-8.293031E7)
            int r1 = r1 * r2
            int r2 = r1 << 16
            r1 = r1 ^ r2
            r2 = r1 & 127(0x7f, float:1.78E-43)
            int r3 = r0.c
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
            if (r10 == 0) goto L60
            int r10 = java.lang.Long.numberOfTrailingZeros(r8)
            int r10 = r10 >> 3
            int r10 = r10 + r1
            r10 = r10 & r3
            int[] r14 = r0.b
            r14 = r14[r10]
            r15 = r19
            if (r14 != r15) goto L59
            goto L6a
        L59:
            r16 = 1
            long r16 = r8 - r16
            long r8 = r8 & r16
            goto L42
        L60:
            long r8 = ~r6
            r10 = 6
            long r8 = r8 << r10
            long r6 = r6 & r8
            long r6 = r6 & r12
            int r6 = (r6 > r14 ? 1 : (r6 == r14 ? 0 : -1))
            if (r6 == 0) goto L6e
            r10 = -1
        L6a:
            if (r10 < 0) goto L6d
            return r11
        L6d:
            return r4
        L6e:
            int r5 = r5 + 8
            int r1 = r1 + r5
            r1 = r1 & r3
            goto L16
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.C0224w.c(int):boolean");
    }

    public final int d(int i) {
        int i2 = this.c;
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

    public final void e(int i) {
        long[] jArr;
        int iMax = i > 0 ? Math.max(7, S.c(i)) : 0;
        this.c = iMax;
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
        this.e = S.a(this.c) - this.d;
        this.b = new int[iMax];
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0058  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean equals(java.lang.Object r18) {
        /*
            r17 = this;
            r0 = r17
            r1 = r18
            r2 = 1
            if (r1 != r0) goto L8
            return r2
        L8:
            boolean r3 = r1 instanceof androidx.collection.C0224w
            r4 = 0
            if (r3 != 0) goto Le
            return r4
        Le:
            androidx.collection.w r1 = (androidx.collection.C0224w) r1
            int r3 = r1.d
            int r5 = r0.d
            if (r3 == r5) goto L17
            return r4
        L17:
            int[] r3 = r0.b
            long[] r5 = r0.a
            int r6 = r5.length
            int r6 = r6 + (-2)
            if (r6 < 0) goto L5d
            r7 = r4
        L21:
            r8 = r5[r7]
            long r10 = ~r8
            r12 = 7
            long r10 = r10 << r12
            long r10 = r10 & r8
            r12 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r10 = r10 & r12
            int r10 = (r10 > r12 ? 1 : (r10 == r12 ? 0 : -1))
            if (r10 == 0) goto L58
            int r10 = r7 - r6
            int r10 = ~r10
            int r10 = r10 >>> 31
            r11 = 8
            int r10 = 8 - r10
            r12 = r4
        L3b:
            if (r12 >= r10) goto L56
            r13 = 255(0xff, double:1.26E-321)
            long r13 = r13 & r8
            r15 = 128(0x80, double:6.3E-322)
            int r13 = (r13 > r15 ? 1 : (r13 == r15 ? 0 : -1))
            if (r13 >= 0) goto L52
            int r13 = r7 << 3
            int r13 = r13 + r12
            r13 = r3[r13]
            boolean r13 = r1.c(r13)
            if (r13 != 0) goto L52
            return r4
        L52:
            long r8 = r8 >> r11
            int r12 = r12 + 1
            goto L3b
        L56:
            if (r10 != r11) goto L5d
        L58:
            if (r7 == r6) goto L5d
            int r7 = r7 + 1
            goto L21
        L5d:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.C0224w.equals(java.lang.Object):boolean");
    }

    public final void f(int i) {
        this.d--;
        long[] jArr = this.a;
        int i2 = this.c;
        int i3 = i >> 3;
        int i4 = (i & 7) << 3;
        long j = (jArr[i3] & (~(255 << i4))) | (254 << i4);
        jArr[i3] = j;
        jArr[(((i - 7) & i2) + (i2 & 7)) >> 3] = j;
    }

    public final int hashCode() {
        int[] iArr = this.b;
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
                        iHashCode = Integer.hashCode(iArr[(i << 3) + i3]) + iHashCode;
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

    /* JADX WARN: Removed duplicated region for block: B:21:0x007d A[PHI: r10
  0x007d: PHI (r10v2 int) = (r10v1 int), (r10v3 int) binds: [B:6:0x003f, B:20:0x007b] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String toString() {
        /*
            r20 = this;
            r0 = r20
            java.lang.String r1 = "separator"
            java.lang.String r2 = ", "
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r1)
            java.lang.String r1 = "prefix"
            java.lang.String r3 = "["
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r1)
            java.lang.String r1 = "postfix"
            java.lang.String r4 = "]"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r1)
            java.lang.String r1 = "truncated"
            java.lang.String r5 = "..."
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r1)
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            r1.append(r3)
            int[] r3 = r0.b
            long[] r6 = r0.a
            int r7 = r6.length
            int r7 = r7 + (-2)
            if (r7 < 0) goto L82
            r9 = 0
            r10 = 0
        L31:
            r11 = r6[r9]
            long r13 = ~r11
            r15 = 7
            long r13 = r13 << r15
            long r13 = r13 & r11
            r15 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r13 = r13 & r15
            int r13 = (r13 > r15 ? 1 : (r13 == r15 ? 0 : -1))
            if (r13 == 0) goto L7d
            int r13 = r9 - r7
            int r13 = ~r13
            int r13 = r13 >>> 31
            r14 = 8
            int r13 = 8 - r13
            r15 = 0
        L4b:
            if (r15 >= r13) goto L7a
            r16 = 255(0xff, double:1.26E-321)
            long r16 = r11 & r16
            r18 = 128(0x80, double:6.3E-322)
            int r16 = (r16 > r18 ? 1 : (r16 == r18 ? 0 : -1))
            if (r16 >= 0) goto L71
            int r16 = r9 << 3
            int r16 = r16 + r15
            r8 = r3[r16]
            r16 = r14
            r14 = -1
            if (r10 != r14) goto L66
            r1.append(r5)
            goto L85
        L66:
            if (r10 == 0) goto L6b
            r1.append(r2)
        L6b:
            r1.append(r8)
            int r10 = r10 + 1
            goto L73
        L71:
            r16 = r14
        L73:
            long r11 = r11 >> r16
            int r15 = r15 + 1
            r14 = r16
            goto L4b
        L7a:
            r8 = r14
            if (r13 != r8) goto L82
        L7d:
            if (r9 == r7) goto L82
            int r9 = r9 + 1
            goto L31
        L82:
            r1.append(r4)
        L85:
            java.lang.String r1 = r1.toString()
            java.lang.String r2 = "toString(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.C0224w.toString():java.lang.String");
    }

    public /* synthetic */ C0224w() {
        this(6);
    }
}
