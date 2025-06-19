package com.mayakapps.kache.collection;

import com.j256.ormlite.stmt.query.SimpleComparison;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class d {
    public long[] a = h.a;
    public Object[] b;
    public Object[] c;
    public int d;
    public int e;
    public final g f;
    public int g;

    public d(int i) {
        Object[] objArr = com.mayakapps.kache.collection.internal.a.b;
        this.b = objArr;
        this.c = objArr;
        this.f = new g(this, 0);
        if (i < 0) {
            throw new IllegalArgumentException("Capacity must be a positive value.");
        }
        i(i == 7 ? 8 : i + ((i - 1) / 7));
    }

    public void a(int i) {
    }

    public void b(int i) {
    }

    public void c(int i) {
    }

    public void d(int i) {
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x006e, code lost:
    
        if (((r7 & ((~r7) << 6)) & (-9187201950435737472L)) == 0) goto L20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0070, code lost:
    
        r11 = -1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean e(java.lang.Object r18) {
        /*
            r17 = this;
            r0 = r17
            r1 = r18
            r2 = 0
            if (r1 == 0) goto Lc
            int r3 = r1.hashCode()
            goto Ld
        Lc:
            r3 = r2
        Ld:
            r4 = -862048943(0xffffffffcc9e2d51, float:-8.293031E7)
            int r3 = r3 * r4
            int r4 = r3 << 16
            r3 = r3 ^ r4
            r4 = r3 & 127(0x7f, float:1.78E-43)
            int r5 = r0.d
            int r3 = r3 >>> 7
            r3 = r3 & r5
            r6 = r2
        L1c:
            long[] r7 = r0.a
            int r8 = r3 >> 3
            r9 = r3 & 7
            int r9 = r9 << 3
            r10 = r7[r8]
            long r10 = r10 >>> r9
            r12 = 1
            int r8 = r8 + r12
            r13 = r7[r8]
            int r7 = 64 - r9
            long r7 = r13 << r7
            long r13 = (long) r9
            long r13 = -r13
            r9 = 63
            long r13 = r13 >> r9
            long r7 = r7 & r13
            long r7 = r7 | r10
            long r9 = (long) r4
            r13 = 72340172838076673(0x101010101010101, double:7.748604185489348E-304)
            long r9 = r9 * r13
            long r9 = r9 ^ r7
            long r13 = r9 - r13
            long r9 = ~r9
            long r9 = r9 & r13
            r13 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r9 = r9 & r13
        L48:
            r15 = 0
            int r11 = (r9 > r15 ? 1 : (r9 == r15 ? 0 : -1))
            if (r11 == 0) goto L67
            int r11 = java.lang.Long.numberOfTrailingZeros(r9)
            int r11 = r11 >> 3
            int r11 = r11 + r3
            r11 = r11 & r5
            java.lang.Object[] r15 = r0.b
            r15 = r15[r11]
            boolean r15 = kotlin.jvm.internal.Intrinsics.b(r15, r1)
            if (r15 == 0) goto L61
            goto L71
        L61:
            r15 = 1
            long r15 = r9 - r15
            long r9 = r9 & r15
            goto L48
        L67:
            long r9 = ~r7
            r11 = 6
            long r9 = r9 << r11
            long r7 = r7 & r9
            long r7 = r7 & r13
            int r7 = (r7 > r15 ? 1 : (r7 == r15 ? 0 : -1))
            if (r7 == 0) goto L75
            r11 = -1
        L71:
            if (r11 < 0) goto L74
            return r12
        L74:
            return r2
        L75:
            int r6 = r6 + 8
            int r3 = r3 + r6
            r3 = r3 & r5
            goto L1c
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.collection.d.e(java.lang.Object):boolean");
    }

    /* JADX WARN: Code restructure failed: missing block: B:42:0x0091, code lost:
    
        return false;
     */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00a3  */
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
            boolean r3 = r1 instanceof com.mayakapps.kache.collection.d
            r4 = 0
            if (r3 != 0) goto Le
            return r4
        Le:
            com.mayakapps.kache.collection.d r1 = (com.mayakapps.kache.collection.d) r1
            int r3 = r1.e
            int r5 = r0.e
            if (r3 == r5) goto L17
            return r4
        L17:
            java.lang.Object[] r3 = r0.b
            java.lang.Object[] r5 = r0.c
            boolean r6 = r0 instanceof com.mayakapps.kache.collection.c
            if (r6 == 0) goto L4f
            r6 = r0
            com.mayakapps.kache.collection.c r6 = (com.mayakapps.kache.collection.c) r6
            androidx.compose.ui.text.android.selection.f r6 = r6.k
            int r7 = r6.b
            java.lang.Object r6 = r6.d
            int[] r6 = (int[]) r6
        L2a:
            r8 = -1
            if (r7 == r8) goto La8
            r8 = r6[r7]
            r9 = r3[r7]
            r7 = r5[r7]
            if (r7 != 0) goto L42
            java.lang.Object r7 = r1.h(r9)
            if (r7 != 0) goto L41
            boolean r7 = r1.e(r9)
            if (r7 != 0) goto L4d
        L41:
            return r4
        L42:
            java.lang.Object r9 = r1.h(r9)
            boolean r7 = r7.equals(r9)
            if (r7 != 0) goto L4d
            return r4
        L4d:
            r7 = r8
            goto L2a
        L4f:
            long[] r6 = r0.a
            int r7 = r6.length
            int r7 = r7 + (-2)
            if (r7 < 0) goto La8
            r8 = r4
        L57:
            r9 = r6[r8]
            long r11 = ~r9
            r13 = 7
            long r11 = r11 << r13
            long r11 = r11 & r9
            r13 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r11 = r11 & r13
            int r11 = (r11 > r13 ? 1 : (r11 == r13 ? 0 : -1))
            if (r11 == 0) goto La3
            int r11 = r8 - r7
            int r11 = ~r11
            int r11 = r11 >>> 31
            r12 = 8
            int r11 = 8 - r11
            r13 = r4
        L71:
            if (r13 >= r11) goto La1
            r14 = 255(0xff, double:1.26E-321)
            long r14 = r14 & r9
            r16 = 128(0x80, double:6.3E-322)
            int r14 = (r14 > r16 ? 1 : (r14 == r16 ? 0 : -1))
            if (r14 >= 0) goto L9d
            int r14 = r8 << 3
            int r14 = r14 + r13
            r15 = r3[r14]
            r14 = r5[r14]
            if (r14 != 0) goto L92
            java.lang.Object r14 = r1.h(r15)
            if (r14 != 0) goto L91
            boolean r14 = r1.e(r15)
            if (r14 != 0) goto L9d
        L91:
            return r4
        L92:
            java.lang.Object r15 = r1.h(r15)
            boolean r14 = r14.equals(r15)
            if (r14 != 0) goto L9d
            return r4
        L9d:
            long r9 = r9 >> r12
            int r13 = r13 + 1
            goto L71
        La1:
            if (r11 != r12) goto La8
        La3:
            if (r8 == r7) goto La8
            int r8 = r8 + 1
            goto L57
        La8:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.collection.d.equals(java.lang.Object):boolean");
    }

    public final int f(int i) {
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

    /* JADX WARN: Removed duplicated region for block: B:30:0x00b9  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int g(java.lang.Object r21) {
        /*
            Method dump skipped, instructions count: 279
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.collection.d.g(java.lang.Object):int");
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x0069, code lost:
    
        if (((r4 & ((~r4) << 6)) & (-9187201950435737472L)) == 0) goto L22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x006b, code lost:
    
        r10 = -1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object h(java.lang.Object r14) {
        /*
            r13 = this;
            r0 = 0
            if (r14 == 0) goto L8
            int r1 = r14.hashCode()
            goto L9
        L8:
            r1 = r0
        L9:
            r2 = -862048943(0xffffffffcc9e2d51, float:-8.293031E7)
            int r1 = r1 * r2
            int r2 = r1 << 16
            r1 = r1 ^ r2
            r2 = r1 & 127(0x7f, float:1.78E-43)
            int r3 = r13.d
            int r1 = r1 >>> 7
        L16:
            r1 = r1 & r3
            long[] r4 = r13.a
            int r5 = r1 >> 3
            r6 = r1 & 7
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
            long r6 = (long) r2
            r8 = 72340172838076673(0x101010101010101, double:7.748604185489348E-304)
            long r6 = r6 * r8
            long r6 = r6 ^ r4
            long r8 = r6 - r8
            long r6 = ~r6
            long r6 = r6 & r8
            r8 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r6 = r6 & r8
        L43:
            r10 = 0
            int r12 = (r6 > r10 ? 1 : (r6 == r10 ? 0 : -1))
            if (r12 == 0) goto L62
            int r10 = java.lang.Long.numberOfTrailingZeros(r6)
            int r10 = r10 >> 3
            int r10 = r10 + r1
            r10 = r10 & r3
            java.lang.Object[] r11 = r13.b
            r11 = r11[r10]
            boolean r11 = kotlin.jvm.internal.Intrinsics.b(r11, r14)
            if (r11 == 0) goto L5c
            goto L6c
        L5c:
            r10 = 1
            long r10 = r6 - r10
            long r6 = r6 & r10
            goto L43
        L62:
            long r6 = ~r4
            r12 = 6
            long r6 = r6 << r12
            long r4 = r4 & r6
            long r4 = r4 & r8
            int r4 = (r4 > r10 ? 1 : (r4 == r10 ? 0 : -1))
            if (r4 == 0) goto L78
            r10 = -1
        L6c:
            if (r10 < 0) goto L76
            java.lang.Object[] r14 = r13.c
            r14 = r14[r10]
            r13.a(r10)
            return r14
        L76:
            r14 = 0
            return r14
        L78:
            int r0 = r0 + 8
            int r1 = r1 + r0
            goto L16
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.collection.d.h(java.lang.Object):java.lang.Object");
    }

    public final int hashCode() {
        Object[] objArr = this.b;
        Object[] objArr2 = this.c;
        if (this instanceof c) {
            androidx.compose.ui.text.android.selection.f fVar = ((c) this).k;
            int i = fVar.b;
            int[] iArr = (int[]) fVar.d;
            int iHashCode = 0;
            while (i != -1) {
                int i2 = iArr[i];
                Object obj = objArr[i];
                Object obj2 = objArr2[i];
                iHashCode += (obj2 != null ? obj2.hashCode() : 0) ^ (obj != null ? obj.hashCode() : 0);
                i = i2;
            }
            return iHashCode;
        }
        long[] jArr = this.a;
        int length = jArr.length - 2;
        if (length < 0) {
            return 0;
        }
        int i3 = 0;
        int iHashCode2 = 0;
        while (true) {
            long j = jArr[i3];
            if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                int i4 = 8 - ((~(i3 - length)) >>> 31);
                for (int i5 = 0; i5 < i4; i5++) {
                    if ((255 & j) < 128) {
                        int i6 = (i3 << 3) + i5;
                        Object obj3 = objArr[i6];
                        Object obj4 = objArr2[i6];
                        iHashCode2 += (obj4 != null ? obj4.hashCode() : 0) ^ (obj3 != null ? obj3.hashCode() : 0);
                    }
                    j >>= 8;
                }
                if (i4 != 8) {
                    return iHashCode2;
                }
            }
            if (i3 == length) {
                return iHashCode2;
            }
            i3++;
        }
    }

    public final void i(int i) {
        long[] jArr;
        if (i > 0) {
            iMax = Math.max(7, i > 0 ? (-1) >>> Integer.numberOfLeadingZeros(i) : 0);
        }
        this.d = iMax;
        if (iMax == 0) {
            jArr = h.a;
        } else {
            jArr = new long[((iMax + 15) & (-8)) >> 3];
            C4930v.q(jArr);
        }
        this.a = jArr;
        int i2 = iMax >> 3;
        long j = 255 << ((iMax & 7) << 3);
        jArr[i2] = (jArr[i2] & (~j)) | j;
        int i3 = this.d;
        this.g = (i3 == 7 ? 6 : i3 - (i3 / 8)) - this.e;
        this.b = new Object[iMax];
        this.c = new Object[iMax];
    }

    public final Object j(Object obj, Object obj2) {
        int iG = g(obj);
        boolean z = iG < 0;
        if (z) {
            iG = ~iG;
        }
        Object[] objArr = this.c;
        Object obj3 = objArr[iG];
        this.b[iG] = obj;
        objArr[iG] = obj2;
        if (z) {
            b(iG);
            return obj3;
        }
        d(iG);
        return obj3;
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x0069, code lost:
    
        if (((r4 & ((~r4) << 6)) & (-9187201950435737472L)) == 0) goto L22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x006b, code lost:
    
        r10 = -1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object k(java.lang.Object r14) {
        /*
            r13 = this;
            r0 = 0
            if (r14 == 0) goto L8
            int r1 = r14.hashCode()
            goto L9
        L8:
            r1 = r0
        L9:
            r2 = -862048943(0xffffffffcc9e2d51, float:-8.293031E7)
            int r1 = r1 * r2
            int r2 = r1 << 16
            r1 = r1 ^ r2
            r2 = r1 & 127(0x7f, float:1.78E-43)
            int r3 = r13.d
            int r1 = r1 >>> 7
        L16:
            r1 = r1 & r3
            long[] r4 = r13.a
            int r5 = r1 >> 3
            r6 = r1 & 7
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
            long r6 = (long) r2
            r8 = 72340172838076673(0x101010101010101, double:7.748604185489348E-304)
            long r6 = r6 * r8
            long r6 = r6 ^ r4
            long r8 = r6 - r8
            long r6 = ~r6
            long r6 = r6 & r8
            r8 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r6 = r6 & r8
        L43:
            r10 = 0
            int r12 = (r6 > r10 ? 1 : (r6 == r10 ? 0 : -1))
            if (r12 == 0) goto L62
            int r10 = java.lang.Long.numberOfTrailingZeros(r6)
            int r10 = r10 >> 3
            int r10 = r10 + r1
            r10 = r10 & r3
            java.lang.Object[] r11 = r13.b
            r11 = r11[r10]
            boolean r11 = kotlin.jvm.internal.Intrinsics.b(r11, r14)
            if (r11 == 0) goto L5c
            goto L6c
        L5c:
            r10 = 1
            long r10 = r6 - r10
            long r6 = r6 & r10
            goto L43
        L62:
            long r6 = ~r4
            r12 = 6
            long r6 = r6 << r12
            long r4 = r4 & r6
            long r4 = r4 & r8
            int r4 = (r4 > r10 ? 1 : (r4 == r10 ? 0 : -1))
            if (r4 == 0) goto L75
            r10 = -1
        L6c:
            if (r10 < 0) goto L73
            java.lang.Object r14 = r13.l(r10)
            return r14
        L73:
            r14 = 0
            return r14
        L75:
            int r0 = r0 + 8
            int r1 = r1 + r0
            goto L16
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.collection.d.k(java.lang.Object):java.lang.Object");
    }

    public final Object l(int i) {
        this.e--;
        long[] jArr = this.a;
        int i2 = i >> 3;
        int i3 = (i & 7) << 3;
        jArr[i2] = (jArr[i2] & (~(255 << i3))) | (254 << i3);
        int i4 = this.d;
        int i5 = ((i - 7) & i4) + (i4 & 7);
        int i6 = i5 >> 3;
        int i7 = (i5 & 7) << 3;
        jArr[i6] = (jArr[i6] & (~(255 << i7))) | (254 << i7);
        this.b[i] = null;
        Object[] objArr = this.c;
        Object obj = objArr[i];
        objArr[i] = null;
        c(i);
        return obj;
    }

    public void m(int i) {
        int i2;
        long[] jArr = this.a;
        Object[] objArr = this.b;
        Object[] objArr2 = this.c;
        int i3 = this.d;
        i(i);
        Object[] objArr3 = this.b;
        Object[] objArr4 = this.c;
        int i4 = 0;
        while (i4 < i3) {
            if (((jArr[i4 >> 3] >> ((i4 & 7) << 3)) & 255) < 128) {
                Object obj = objArr[i4];
                int iHashCode = (obj != null ? obj.hashCode() : 0) * (-862048943);
                int i5 = iHashCode ^ (iHashCode << 16);
                int iF = f(i5 >>> 7);
                long j = i5 & 127;
                long[] jArr2 = this.a;
                int i6 = iF >> 3;
                int i7 = (iF & 7) << 3;
                i2 = i4;
                jArr2[i6] = (jArr2[i6] & (~(255 << i7))) | (j << i7);
                int i8 = this.d;
                int i9 = ((iF - 7) & i8) + (i8 & 7);
                int i10 = i9 >> 3;
                int i11 = (i9 & 7) << 3;
                jArr2[i10] = (jArr2[i10] & (~(255 << i11))) | (j << i11);
                objArr3[iF] = obj;
                objArr4[iF] = objArr2[i2];
            } else {
                i2 = i4;
            }
            i4 = i2 + 1;
        }
    }

    public final String toString() {
        Object[] objArr;
        Object[] objArr2;
        int i;
        if (this.e == 0) {
            return "{}";
        }
        StringBuilder sb = new StringBuilder("{");
        Object[] objArr3 = this.b;
        Object[] objArr4 = this.c;
        if (this instanceof c) {
            androidx.compose.ui.text.android.selection.f fVar = ((c) this).k;
            int i2 = fVar.b;
            int[] iArr = (int[]) fVar.d;
            int i3 = 0;
            while (i2 != -1) {
                int i4 = iArr[i2];
                Object obj = objArr3[i2];
                Object obj2 = objArr4[i2];
                if (obj == this) {
                    obj = "(this)";
                }
                sb.append(obj);
                sb.append(SimpleComparison.EQUAL_TO_OPERATION);
                if (obj2 == this) {
                    obj2 = "(this)";
                }
                sb.append(obj2);
                i3++;
                if (i3 < this.e) {
                    sb.append(", ");
                }
                i2 = i4;
            }
        } else {
            long[] jArr = this.a;
            int length = jArr.length - 2;
            if (length >= 0) {
                int i5 = 0;
                int i6 = 0;
                while (true) {
                    long j = jArr[i5];
                    if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                        int i7 = 8;
                        int i8 = 8 - ((~(i5 - length)) >>> 31);
                        int i9 = 0;
                        while (i9 < i8) {
                            if ((j & 255) < 128) {
                                int i10 = (i5 << 3) + i9;
                                i = i7;
                                Object obj3 = objArr3[i10];
                                objArr2 = objArr3;
                                Object obj4 = objArr4[i10];
                                if (obj3 == this) {
                                    obj3 = "(this)";
                                }
                                sb.append(obj3);
                                sb.append(SimpleComparison.EQUAL_TO_OPERATION);
                                if (obj4 == this) {
                                    obj4 = "(this)";
                                }
                                sb.append(obj4);
                                i6++;
                                if (i6 < this.e) {
                                    sb.append(", ");
                                }
                            } else {
                                objArr2 = objArr3;
                                i = i7;
                            }
                            j >>= i;
                            i9++;
                            i7 = i;
                            objArr3 = objArr2;
                        }
                        objArr = objArr3;
                        if (i8 != i7) {
                            break;
                        }
                    } else {
                        objArr = objArr3;
                    }
                    if (i5 == length) {
                        break;
                    }
                    i5++;
                    objArr3 = objArr;
                }
            }
        }
        sb.append('}');
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }
}
