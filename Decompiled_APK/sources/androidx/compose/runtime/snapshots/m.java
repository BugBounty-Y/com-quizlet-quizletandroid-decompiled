package androidx.compose.runtime.snapshots;

import androidx.appcompat.widget.C0122z;
import androidx.collection.J;
import androidx.compose.foundation.lazy.layout.n0;
import java.util.HashMap;
import kotlin.collections.C4930v;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class m {
    public static final com.quizlet.data.repository.classfolder.e a = new com.quizlet.data.repository.classfolder.e(2);
    public static final Object b = new Object();
    public static l c;
    public static long d;
    public static final n0 e;
    public static final C0122z f;
    public static Object g;
    public static Object h;
    public static final C0823c i;
    public static final androidx.compose.runtime.internal.a j;

    static {
        l lVar = l.e;
        c = lVar;
        d = 1 + 1;
        n0 n0Var = new n0();
        n0Var.c = new long[16];
        n0Var.d = new int[16];
        int[] iArr = new int[16];
        int i2 = 0;
        while (i2 < 16) {
            int i3 = i2 + 1;
            iArr[i2] = i3;
            i2 = i3;
        }
        n0Var.e = iArr;
        e = n0Var;
        C0122z c0122z = new C0122z(4, (char) 0);
        c0122z.c = new int[16];
        c0122z.d = new androidx.compose.runtime.internal.m[16];
        f = c0122z;
        K k = K.a;
        g = k;
        h = k;
        long j2 = d;
        d = 1 + j2;
        C0823c c0823c = new C0823c(j2, lVar, null, C0821a.b);
        c = c.h(c0823c.b);
        i = c0823c;
        j = new androidx.compose.runtime.internal.a(0);
    }

    public static final void a() {
        f(C0821a.c);
    }

    public static final Function1 b(Function1 function1, Function1 function12) {
        return (function1 == null || function12 == null || function1 == function12) ? function1 == null ? function12 : function1 : new C0822b(function1, function12, 2);
    }

    public static final HashMap c(long j2, C0824d c0824d, l lVar) {
        long[] jArr;
        l lVar2;
        long[] jArr2;
        l lVar3;
        int i2;
        B bS;
        long j3 = j2;
        J jX = c0824d.x();
        if (jX != null) {
            l lVarG = c0824d.d().h(c0824d.g()).g(c0824d.j);
            Object[] objArr = jX.b;
            long[] jArr3 = jX.a;
            int length = jArr3.length - 2;
            if (length >= 0) {
                int i3 = 0;
                HashMap map = null;
                while (true) {
                    long j4 = jArr3[i3];
                    if ((((~j4) << 7) & j4 & (-9187201950435737472L)) != -9187201950435737472L) {
                        int i4 = 8;
                        int i5 = 8 - ((~(i3 - length)) >>> 31);
                        int i6 = 0;
                        while (i6 < i5) {
                            if ((j4 & 255) < 128) {
                                z zVar = (z) objArr[(i3 << 3) + i6];
                                B b2 = zVar.b();
                                jArr2 = jArr3;
                                i2 = i4;
                                B bS2 = s(b2, j3, lVar);
                                if (bS2 == null || (bS = s(b2, j3, lVarG)) == null || bS2.equals(bS)) {
                                    lVar3 = lVarG;
                                } else {
                                    lVar3 = lVarG;
                                    B bS3 = s(b2, c0824d.g(), c0824d.d());
                                    if (bS3 == null) {
                                        r();
                                        throw null;
                                    }
                                    B bG = zVar.g(bS, bS2, bS3);
                                    if (bG == null) {
                                        return null;
                                    }
                                    if (map == null) {
                                        map = new HashMap();
                                    }
                                    map.put(bS2, bG);
                                    map = map;
                                }
                            } else {
                                jArr2 = jArr3;
                                lVar3 = lVarG;
                                i2 = i4;
                            }
                            j4 >>= i2;
                            i6++;
                            j3 = j2;
                            i4 = i2;
                            jArr3 = jArr2;
                            lVarG = lVar3;
                        }
                        jArr = jArr3;
                        lVar2 = lVarG;
                        if (i5 != i4) {
                            return map;
                        }
                    } else {
                        jArr = jArr3;
                        lVar2 = lVarG;
                    }
                    if (i3 == length) {
                        return map;
                    }
                    i3++;
                    j3 = j2;
                    jArr3 = jArr;
                    lVarG = lVar2;
                }
            }
        }
        return null;
    }

    public static final void d(h hVar) {
        long j2;
        if (c.e(hVar.g())) {
            return;
        }
        StringBuilder sb = new StringBuilder("Snapshot is not open: snapshotId=");
        sb.append(hVar.g());
        sb.append(", disposed=");
        sb.append(hVar.c);
        sb.append(", applied=");
        C0824d c0824d = hVar instanceof C0824d ? (C0824d) hVar : null;
        sb.append(c0824d != null ? Boolean.valueOf(c0824d.m) : "read-only");
        sb.append(", lowestPin=");
        synchronized (b) {
            n0 n0Var = e;
            j2 = n0Var.a > 0 ? ((long[]) n0Var.c)[0] : -1L;
        }
        sb.append(j2);
        throw new IllegalStateException(sb.toString().toString());
    }

    public static final l e(l lVar, long j2, long j3) {
        while (j2 < j3) {
            lVar = lVar.h(j2);
            j2++;
        }
        return lVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x008e  */
    /* JADX WARN: Type inference failed for: r6v2, types: [java.lang.Object, java.util.Collection, java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object f(kotlin.jvm.functions.Function1 r17) {
        /*
            r0 = 1
            androidx.compose.runtime.snapshots.c r1 = androidx.compose.runtime.snapshots.m.i
            java.lang.Object r2 = androidx.compose.runtime.snapshots.m.b
            monitor-enter(r2)
            androidx.collection.J r3 = r1.h     // Catch: java.lang.Throwable -> L12
            if (r3 == 0) goto Lf
            androidx.compose.runtime.internal.a r4 = androidx.compose.runtime.snapshots.m.j     // Catch: java.lang.Throwable -> L12
            r4.addAndGet(r0)     // Catch: java.lang.Throwable -> L12
        Lf:
            r4 = r17
            goto L15
        L12:
            r0 = move-exception
            goto L98
        L15:
            java.lang.Object r4 = v(r1, r4)     // Catch: java.lang.Throwable -> L12
            monitor-exit(r2)
            r2 = 0
            if (r3 == 0) goto L45
            r5 = -1
            java.lang.Object r6 = androidx.compose.runtime.snapshots.m.g     // Catch: java.lang.Throwable -> L37
            int r7 = r6.size()     // Catch: java.lang.Throwable -> L37
            r8 = r2
        L25:
            if (r8 >= r7) goto L39
            java.lang.Object r9 = r6.get(r8)     // Catch: java.lang.Throwable -> L37
            kotlin.jvm.functions.Function2 r9 = (kotlin.jvm.functions.Function2) r9     // Catch: java.lang.Throwable -> L37
            androidx.compose.runtime.collection.e r10 = new androidx.compose.runtime.collection.e     // Catch: java.lang.Throwable -> L37
            r10.<init>(r3)     // Catch: java.lang.Throwable -> L37
            r9.invoke(r10, r1)     // Catch: java.lang.Throwable -> L37
            int r8 = r8 + r0
            goto L25
        L37:
            r0 = move-exception
            goto L3f
        L39:
            androidx.compose.runtime.internal.a r1 = androidx.compose.runtime.snapshots.m.j
            r1.addAndGet(r5)
            goto L45
        L3f:
            androidx.compose.runtime.internal.a r1 = androidx.compose.runtime.snapshots.m.j
            r1.addAndGet(r5)
            throw r0
        L45:
            java.lang.Object r1 = androidx.compose.runtime.snapshots.m.b
            monitor-enter(r1)
            g()     // Catch: java.lang.Throwable -> L87
            if (r3 == 0) goto L94
            java.lang.Object[] r5 = r3.b     // Catch: java.lang.Throwable -> L87
            long[] r3 = r3.a     // Catch: java.lang.Throwable -> L87
            int r6 = r3.length     // Catch: java.lang.Throwable -> L87
            int r6 = r6 + (-2)
            if (r6 < 0) goto L92
            r7 = r2
        L57:
            r8 = r3[r7]     // Catch: java.lang.Throwable -> L87
            long r10 = ~r8     // Catch: java.lang.Throwable -> L87
            r12 = 7
            long r10 = r10 << r12
            long r10 = r10 & r8
            r12 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r10 = r10 & r12
            int r10 = (r10 > r12 ? 1 : (r10 == r12 ? 0 : -1))
            if (r10 == 0) goto L8e
            int r10 = r7 - r6
            int r10 = ~r10     // Catch: java.lang.Throwable -> L87
            int r10 = r10 >>> 31
            r11 = 8
            int r10 = 8 - r10
            r12 = r2
        L71:
            if (r12 >= r10) goto L8c
            r13 = 255(0xff, double:1.26E-321)
            long r13 = r13 & r8
            r15 = 128(0x80, double:6.3E-322)
            int r13 = (r13 > r15 ? 1 : (r13 == r15 ? 0 : -1))
            if (r13 >= 0) goto L89
            int r13 = r7 << 3
            int r13 = r13 + r12
            r13 = r5[r13]     // Catch: java.lang.Throwable -> L87
            androidx.compose.runtime.snapshots.z r13 = (androidx.compose.runtime.snapshots.z) r13     // Catch: java.lang.Throwable -> L87
            q(r13)     // Catch: java.lang.Throwable -> L87
            goto L89
        L87:
            r0 = move-exception
            goto L96
        L89:
            long r8 = r8 >> r11
            int r12 = r12 + r0
            goto L71
        L8c:
            if (r10 != r11) goto L92
        L8e:
            if (r7 == r6) goto L92
            int r7 = r7 + r0
            goto L57
        L92:
            kotlin.Unit r0 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L87
        L94:
            monitor-exit(r1)
            return r4
        L96:
            monitor-exit(r1)
            throw r0
        L98:
            monitor-exit(r2)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.m.f(kotlin.jvm.functions.Function1):java.lang.Object");
    }

    public static final void g() {
        C0122z c0122z = f;
        int i2 = c0122z.b;
        int i3 = 0;
        int i4 = 0;
        while (true) {
            if (i3 >= i2) {
                break;
            }
            androidx.compose.runtime.internal.m mVar = ((androidx.compose.runtime.internal.m[]) c0122z.d)[i3];
            Object obj = mVar != null ? mVar.get() : null;
            if (obj != null && p((z) obj)) {
                if (i4 != i3) {
                    ((androidx.compose.runtime.internal.m[]) c0122z.d)[i4] = mVar;
                    int[] iArr = (int[]) c0122z.c;
                    iArr[i4] = iArr[i3];
                }
                i4++;
            }
            i3++;
        }
        for (int i5 = i4; i5 < i2; i5++) {
            ((androidx.compose.runtime.internal.m[]) c0122z.d)[i5] = null;
            ((int[]) c0122z.c)[i5] = 0;
        }
        if (i4 != i2) {
            c0122z.b = i4;
        }
    }

    public static final h h(h hVar, Function1 function1, boolean z) {
        boolean z2 = hVar instanceof C0824d;
        if (z2 || hVar == null) {
            return new E(z2 ? (C0824d) hVar : null, function1, null, false, z);
        }
        return new F(hVar, function1, z);
    }

    public static final B i(B b2) {
        B bS;
        h hVarK = k();
        B bS2 = s(b2, hVarK.g(), hVarK.d());
        if (bS2 != null) {
            return bS2;
        }
        synchronized (b) {
            h hVarK2 = k();
            bS = s(b2, hVarK2.g(), hVarK2.d());
        }
        if (bS != null) {
            return bS;
        }
        r();
        throw null;
    }

    public static final B j(B b2, h hVar) {
        B bS;
        B bS2 = s(b2, hVar.g(), hVar.d());
        if (bS2 != null) {
            return bS2;
        }
        synchronized (b) {
            bS = s(b2, hVar.g(), hVar.d());
        }
        if (bS != null) {
            return bS;
        }
        r();
        throw null;
    }

    public static final h k() {
        h hVar = (h) a.c();
        return hVar == null ? i : hVar;
    }

    public static final Function1 l(Function1 function1, Function1 function12, boolean z) {
        if (!z) {
            function12 = null;
        }
        return (function1 == null || function12 == null || function1 == function12) ? function1 == null ? function12 : function1 : new C0822b(function1, function12, 1);
    }

    /* JADX WARN: Code restructure failed: missing block: B:33:0x0065, code lost:
    
        r6 = r0;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.runtime.snapshots.B m(androidx.compose.runtime.snapshots.B r16, androidx.compose.runtime.snapshots.z r17) {
        /*
            androidx.compose.runtime.snapshots.B r0 = r17.b()
            long r1 = androidx.compose.runtime.snapshots.m.d
            androidx.compose.foundation.lazy.layout.n0 r3 = androidx.compose.runtime.snapshots.m.e
            int r4 = r3.a
            r5 = 0
            if (r4 <= 0) goto L14
            java.lang.Object r1 = r3.c
            long[] r1 = (long[]) r1
            r2 = r1[r5]
            r1 = r2
        L14:
            r3 = 1
            long r1 = r1 - r3
            r6 = 0
            r7 = r6
        L19:
            if (r0 == 0) goto L6c
            long r8 = r0.a
            r10 = 0
            int r12 = (r8 > r10 ? 1 : (r8 == r10 ? 0 : -1))
            if (r12 != 0) goto L24
            goto L65
        L24:
            int r12 = (r8 > r10 ? 1 : (r8 == r10 ? 0 : -1))
            if (r12 == 0) goto L69
            int r12 = (r8 > r1 ? 1 : (r8 == r1 ? 0 : -1))
            if (r12 > 0) goto L69
            long r8 = r8 - r10
            int r12 = (r8 > r10 ? 1 : (r8 == r10 ? 0 : -1))
            r13 = 64
            r15 = 1
            if (r12 < 0) goto L43
            int r12 = (r8 > r13 ? 1 : (r8 == r13 ? 0 : -1))
            if (r12 >= 0) goto L43
            int r8 = (int) r8
            long r8 = r3 << r8
            long r8 = r8 & r10
            int r8 = (r8 > r10 ? 1 : (r8 == r10 ? 0 : -1))
            if (r8 == 0) goto L41
            goto L57
        L41:
            r15 = r5
            goto L57
        L43:
            int r12 = (r8 > r13 ? 1 : (r8 == r13 ? 0 : -1))
            if (r12 < 0) goto L41
            r12 = 128(0x80, double:6.3E-322)
            int r12 = (r8 > r12 ? 1 : (r8 == r12 ? 0 : -1))
            if (r12 >= 0) goto L41
            int r8 = (int) r8
            int r8 = r8 + (-64)
            long r8 = r3 << r8
            long r8 = r8 & r10
            int r8 = (r8 > r10 ? 1 : (r8 == r10 ? 0 : -1))
            if (r8 == 0) goto L41
        L57:
            if (r15 != 0) goto L69
            if (r7 != 0) goto L5d
            r7 = r0
            goto L69
        L5d:
            long r1 = r0.a
            long r3 = r7.a
            int r1 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r1 >= 0) goto L67
        L65:
            r6 = r0
            goto L6c
        L67:
            r6 = r7
            goto L6c
        L69:
            androidx.compose.runtime.snapshots.B r0 = r0.b
            goto L19
        L6c:
            r0 = 9223372036854775807(0x7fffffffffffffff, double:NaN)
            if (r6 == 0) goto L76
            r6.a = r0
            return r6
        L76:
            r2 = r16
            androidx.compose.runtime.snapshots.B r0 = r2.b(r0)
            androidx.compose.runtime.snapshots.B r1 = r17.b()
            r0.b = r1
            r1 = r17
            r1.a(r0)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.m.m(androidx.compose.runtime.snapshots.B, androidx.compose.runtime.snapshots.z):androidx.compose.runtime.snapshots.B");
    }

    public static final void n(h hVar, z zVar) {
        hVar.t(hVar.h() + 1);
        Function1 function1I = hVar.i();
        if (function1I != null) {
            function1I.invoke(zVar);
        }
    }

    public static final B o(B b2, A a2, h hVar, B b3) {
        B bM;
        if (hVar.f()) {
            hVar.n(a2);
        }
        long jG = hVar.g();
        if (b3.a == jG) {
            return b3;
        }
        synchronized (b) {
            bM = m(b2, a2);
        }
        bM.a = jG;
        if (b3.a != 1) {
            hVar.n(a2);
        }
        return bM;
    }

    public static final boolean p(z zVar) {
        B b2;
        long j2 = d;
        n0 n0Var = e;
        if (n0Var.a > 0) {
            j2 = ((long[]) n0Var.c)[0];
        }
        B b3 = null;
        B b4 = null;
        int i2 = 0;
        for (B b5 = zVar.b(); b5 != null; b5 = b5.b) {
            long j3 = b5.a;
            if (j3 != 0) {
                if (j3 >= j2) {
                    i2++;
                } else if (b3 == null) {
                    i2++;
                    b3 = b5;
                } else {
                    if (j3 < b3.a) {
                        b2 = b3;
                        b3 = b5;
                    } else {
                        b2 = b5;
                    }
                    if (b4 == null) {
                        b4 = zVar.b();
                        B b6 = b4;
                        while (true) {
                            if (b4 == null) {
                                b4 = b6;
                                break;
                            }
                            long j4 = b4.a;
                            if (j4 >= j2) {
                                break;
                            }
                            if (b6.a < j4) {
                                b6 = b4;
                            }
                            b4 = b4.b;
                        }
                    }
                    b3.a = 0L;
                    b3.a(b4);
                    b3 = b2;
                }
            }
        }
        return i2 > 1;
    }

    public static final void q(z zVar) {
        if (p(zVar)) {
            C0122z c0122z = f;
            int i2 = c0122z.b;
            int iIdentityHashCode = System.identityHashCode(zVar);
            int i3 = -1;
            if (i2 > 0) {
                int i4 = c0122z.b - 1;
                int i5 = 0;
                while (true) {
                    if (i5 > i4) {
                        i3 = -(i5 + 1);
                        break;
                    }
                    int i6 = (i5 + i4) >>> 1;
                    int i7 = ((int[]) c0122z.c)[i6];
                    if (i7 < iIdentityHashCode) {
                        i5 = i6 + 1;
                    } else if (i7 > iIdentityHashCode) {
                        i4 = i6 - 1;
                    } else {
                        androidx.compose.runtime.internal.m mVar = ((androidx.compose.runtime.internal.m[]) c0122z.d)[i6];
                        if (zVar == (mVar != null ? mVar.get() : null)) {
                            i3 = i6;
                        } else {
                            for (int i8 = i6 - 1; -1 < i8 && ((int[]) c0122z.c)[i8] == iIdentityHashCode; i8--) {
                                androidx.compose.runtime.internal.m mVar2 = ((androidx.compose.runtime.internal.m[]) c0122z.d)[i8];
                                if ((mVar2 != null ? mVar2.get() : null) == zVar) {
                                    i3 = i8;
                                    break;
                                }
                            }
                            i6++;
                            int i9 = c0122z.b;
                            while (true) {
                                if (i6 >= i9) {
                                    i3 = -(c0122z.b + 1);
                                    break;
                                } else {
                                    if (((int[]) c0122z.c)[i6] != iIdentityHashCode) {
                                        i3 = -(i6 + 1);
                                        break;
                                    }
                                    androidx.compose.runtime.internal.m mVar3 = ((androidx.compose.runtime.internal.m[]) c0122z.d)[i6];
                                    if ((mVar3 != null ? mVar3.get() : null) == zVar) {
                                        break;
                                    } else {
                                        i6++;
                                    }
                                }
                            }
                            i3 = i6;
                        }
                    }
                }
                if (i3 >= 0) {
                    return;
                }
            }
            int i10 = -(i3 + 1);
            androidx.compose.runtime.internal.m[] mVarArr = (androidx.compose.runtime.internal.m[]) c0122z.d;
            int length = mVarArr.length;
            if (i2 == length) {
                int i11 = length * 2;
                androidx.compose.runtime.internal.m[] mVarArr2 = new androidx.compose.runtime.internal.m[i11];
                int[] iArr = new int[i11];
                int i12 = i10 + 1;
                System.arraycopy(mVarArr, i10, mVarArr2, i12, i2 - i10);
                System.arraycopy((androidx.compose.runtime.internal.m[]) c0122z.d, 0, mVarArr2, 0, i10);
                C4930v.e(i12, i10, i2, (int[]) c0122z.c, iArr);
                C4930v.i(0, i10, 6, (int[]) c0122z.c, iArr);
                c0122z.d = mVarArr2;
                c0122z.c = iArr;
            } else {
                int i13 = i10 + 1;
                System.arraycopy(mVarArr, i10, mVarArr, i13, i2 - i10);
                int[] iArr2 = (int[]) c0122z.c;
                C4930v.e(i13, i10, i2, iArr2, iArr2);
            }
            ((androidx.compose.runtime.internal.m[]) c0122z.d)[i10] = new androidx.compose.runtime.internal.m(zVar);
            ((int[]) c0122z.c)[i10] = iIdentityHashCode;
            c0122z.b++;
        }
    }

    public static final void r() {
        throw new IllegalStateException("Reading a state that was created after the snapshot was taken or in a snapshot that has not yet been applied");
    }

    public static final B s(B b2, long j2, l lVar) {
        B b3 = null;
        while (b2 != null) {
            long j3 = b2.a;
            if (j3 != 0 && j3 <= j2 && !lVar.e(j3) && (b3 == null || b3.a < b2.a)) {
                b3 = b2;
            }
            b2 = b2.b;
        }
        if (b3 != null) {
            return b3;
        }
        return null;
    }

    public static final B t(B b2, z zVar) {
        B bS;
        h hVarK = k();
        Function1 function1E = hVarK.e();
        if (function1E != null) {
            function1E.invoke(zVar);
        }
        B bS2 = s(b2, hVarK.g(), hVarK.d());
        if (bS2 != null) {
            return bS2;
        }
        synchronized (b) {
            h hVarK2 = k();
            B b3 = zVar.b();
            Intrinsics.e(b3, "null cannot be cast to non-null type T of androidx.compose.runtime.snapshots.SnapshotKt.readable");
            bS = s(b3, hVarK2.g(), hVarK2.d());
            if (bS == null) {
                r();
                throw null;
            }
        }
        return bS;
    }

    public static final void u(int i2) {
        n0 n0Var = e;
        int i3 = ((int[]) n0Var.e)[i2];
        n0Var.c(i3, n0Var.a - 1);
        n0Var.a--;
        long[] jArr = (long[]) n0Var.c;
        long j2 = jArr[i3];
        int i4 = i3;
        while (i4 > 0) {
            int i5 = ((i4 + 1) >> 1) - 1;
            if (jArr[i5] <= j2) {
                break;
            }
            n0Var.c(i5, i4);
            i4 = i5;
        }
        long[] jArr2 = (long[]) n0Var.c;
        int i6 = n0Var.a >> 1;
        while (i3 < i6) {
            int i7 = (i3 + 1) << 1;
            int i8 = i7 - 1;
            if (i7 < n0Var.a) {
                long j3 = jArr2[i7];
                if (j3 < jArr2[i8]) {
                    if (j3 >= jArr2[i3]) {
                        break;
                    }
                    n0Var.c(i7, i3);
                    i3 = i7;
                }
            }
            if (jArr2[i8] >= jArr2[i3]) {
                break;
            }
            n0Var.c(i8, i3);
            i3 = i8;
        }
        ((int[]) n0Var.e)[i2] = n0Var.b;
        n0Var.b = i2;
    }

    public static final Object v(C0823c c0823c, Function1 function1) {
        long j2 = c0823c.b;
        Object objInvoke = function1.invoke(c.b(j2));
        long j3 = d;
        d = 1 + j3;
        l lVarB = c.b(j2);
        c = lVarB;
        c0823c.b = j3;
        c0823c.a = lVarB;
        c0823c.g = 0;
        c0823c.h = null;
        c0823c.o();
        c = c.h(j3);
        return objInvoke;
    }

    public static final B w(B b2, z zVar, h hVar) {
        B bS;
        if (hVar.f()) {
            hVar.n(zVar);
        }
        long jG = hVar.g();
        B bS2 = s(b2, jG, hVar.d());
        if (bS2 == null) {
            r();
            throw null;
        }
        if (bS2.a == hVar.g()) {
            return bS2;
        }
        synchronized (b) {
            bS = s(zVar.b(), jG, hVar.d());
            if (bS == null) {
                r();
                throw null;
            }
            if (bS.a != jG) {
                B bM = m(bS, zVar);
                bM.a(bS);
                bM.a = hVar.g();
                bS = bM;
            }
        }
        if (bS2.a != 1) {
            hVar.n(zVar);
        }
        return bS;
    }
}
