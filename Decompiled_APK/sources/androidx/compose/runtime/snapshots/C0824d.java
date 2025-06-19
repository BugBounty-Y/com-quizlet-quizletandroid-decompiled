package androidx.compose.runtime.snapshots;

import androidx.collection.J;
import androidx.collection.U;
import androidx.compose.runtime.AbstractC0805k0;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.runtime.snapshots.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C0824d extends h {
    public static final int[] n = new int[0];
    public final Function1 e;
    public final Function1 f;
    public int g;
    public J h;
    public ArrayList i;
    public l j;
    public int[] k;
    public int l;
    public boolean m;

    public C0824d(long j, l lVar, Function1 function1, Function1 function12) {
        super(j, lVar);
        this.e = function1;
        this.f = function12;
        this.j = l.e;
        this.k = n;
        this.l = 1;
    }

    public final void A(long j) {
        synchronized (m.b) {
            this.j = this.j.h(j);
            Unit unit = Unit.a;
        }
    }

    public void B(J j) {
        this.h = j;
    }

    public C0824d C(Function1 function1, Function1 function12) throws Throwable {
        if (this.c) {
            AbstractC0805k0.a("Cannot use a disposed snapshot");
        }
        if (this.m && this.d < 0) {
            AbstractC0805k0.b("Unsupported operation on a disposed or applied snapshot");
        }
        A(g());
        Object obj = m.b;
        synchronized (obj) {
            try {
                long j = m.d;
                m.d = j + 1;
                m.c = m.c.h(j);
                l lVarD = d();
                r(lVarD.h(j));
                try {
                    C0825e c0825e = new C0825e(j, m.e(lVarD, g() + 1, j), m.l(function1, e(), true), m.b(function12, i()), this);
                    if (this.m || this.c) {
                        return c0825e;
                    }
                    long jG = g();
                    synchronized (obj) {
                        long j2 = m.d;
                        m.d = j2 + 1;
                        s(j2);
                        m.c = m.c.h(g());
                        Unit unit = Unit.a;
                    }
                    r(m.e(d(), jG + 1, g()));
                    return c0825e;
                } catch (Throwable th) {
                    th = th;
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        }
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void b() {
        m.c = m.c.b(g()).a(this.j);
    }

    @Override // androidx.compose.runtime.snapshots.h
    public void c() {
        if (this.c) {
            return;
        }
        super.c();
        l();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public boolean f() {
        return false;
    }

    @Override // androidx.compose.runtime.snapshots.h
    public int h() {
        return this.g;
    }

    @Override // androidx.compose.runtime.snapshots.h
    public Function1 i() {
        return this.f;
    }

    @Override // androidx.compose.runtime.snapshots.h
    public void k() {
        this.l++;
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x008c  */
    @Override // androidx.compose.runtime.snapshots.h
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void l() {
        /*
            r17 = this;
            r0 = r17
            int r1 = r0.l
            if (r1 <= 0) goto L7
            goto Lc
        L7:
            java.lang.String r1 = "no pending nested snapshots"
            androidx.compose.runtime.AbstractC0805k0.a(r1)
        Lc:
            int r1 = r0.l
            int r1 = r1 + (-1)
            r0.l = r1
            if (r1 != 0) goto L94
            boolean r1 = r0.m
            if (r1 != 0) goto L94
            androidx.collection.J r1 = r0.x()
            if (r1 == 0) goto L91
            boolean r2 = r0.m
            if (r2 == 0) goto L27
            java.lang.String r2 = "Unsupported operation on a snapshot that has been applied"
            androidx.compose.runtime.AbstractC0805k0.b(r2)
        L27:
            r2 = 0
            r0.B(r2)
            long r2 = r0.g()
            java.lang.Object[] r4 = r1.b
            long[] r1 = r1.a
            int r5 = r1.length
            int r5 = r5 + (-2)
            if (r5 < 0) goto L91
            r7 = 0
        L39:
            r8 = r1[r7]
            long r10 = ~r8
            r12 = 7
            long r10 = r10 << r12
            long r10 = r10 & r8
            r12 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r10 = r10 & r12
            int r10 = (r10 > r12 ? 1 : (r10 == r12 ? 0 : -1))
            if (r10 == 0) goto L8c
            int r10 = r7 - r5
            int r10 = ~r10
            int r10 = r10 >>> 31
            r11 = 8
            int r10 = 8 - r10
            r12 = 0
        L53:
            if (r12 >= r10) goto L8a
            r13 = 255(0xff, double:1.26E-321)
            long r13 = r13 & r8
            r15 = 128(0x80, double:6.3E-322)
            int r13 = (r13 > r15 ? 1 : (r13 == r15 ? 0 : -1))
            if (r13 >= 0) goto L86
            int r13 = r7 << 3
            int r13 = r13 + r12
            r13 = r4[r13]
            androidx.compose.runtime.snapshots.z r13 = (androidx.compose.runtime.snapshots.z) r13
            androidx.compose.runtime.snapshots.B r13 = r13.b()
        L69:
            if (r13 == 0) goto L86
            long r14 = r13.a
            int r16 = (r14 > r2 ? 1 : (r14 == r2 ? 0 : -1))
            if (r16 == 0) goto L7d
            androidx.compose.runtime.snapshots.l r6 = r0.j
            java.lang.Long r14 = java.lang.Long.valueOf(r14)
            boolean r6 = kotlin.collections.CollectionsKt.F(r6, r14)
            if (r6 == 0) goto L83
        L7d:
            com.quizlet.data.repository.classfolder.e r6 = androidx.compose.runtime.snapshots.m.a
            r14 = 0
            r13.a = r14
        L83:
            androidx.compose.runtime.snapshots.B r13 = r13.b
            goto L69
        L86:
            long r8 = r8 >> r11
            int r12 = r12 + 1
            goto L53
        L8a:
            if (r10 != r11) goto L91
        L8c:
            if (r7 == r5) goto L91
            int r7 = r7 + 1
            goto L39
        L91:
            r0.a()
        L94:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.C0824d.l():void");
    }

    @Override // androidx.compose.runtime.snapshots.h
    public void m() {
        if (this.m || this.c) {
            return;
        }
        v();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public void n(z zVar) {
        J jX = x();
        if (jX == null) {
            int i = U.a;
            jX = new J();
            B(jX);
        }
        jX.a(zVar);
    }

    @Override // androidx.compose.runtime.snapshots.h
    public final void p() {
        int length = this.k.length;
        for (int i = 0; i < length; i++) {
            m.u(this.k[i]);
        }
        o();
    }

    @Override // androidx.compose.runtime.snapshots.h
    public void t(int i) {
        this.g = i;
    }

    @Override // androidx.compose.runtime.snapshots.h
    public h u(Function1 function1) throws Throwable {
        if (this.c) {
            AbstractC0805k0.a("Cannot use a disposed snapshot");
        }
        if (this.m && this.d < 0) {
            AbstractC0805k0.b("Unsupported operation on a disposed or applied snapshot");
        }
        long jG = g();
        boolean z = this instanceof C0823c;
        A(g());
        Object obj = m.b;
        synchronized (obj) {
            try {
                long j = m.d;
                m.d = j + 1;
                m.c = m.c.h(j);
                try {
                    C0826f c0826f = new C0826f(j, m.e(d(), jG + 1, j), m.l(function1, e(), true), this);
                    if (this.m || this.c) {
                        return c0826f;
                    }
                    long jG2 = g();
                    synchronized (obj) {
                        long j2 = m.d;
                        m.d = j2 + 1;
                        s(j2);
                        m.c = m.c.h(g());
                        Unit unit = Unit.a;
                    }
                    r(m.e(d(), jG2 + 1, g()));
                    return c0826f;
                } catch (Throwable th) {
                    th = th;
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        }
    }

    public final void v() {
        A(g());
        Unit unit = Unit.a;
        if (this.m || this.c) {
            return;
        }
        long jG = g();
        synchronized (m.b) {
            long j = m.d;
            m.d = j + 1;
            s(j);
            m.c = m.c.h(g());
        }
        r(m.e(d(), jG + 1, g()));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0154  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0164 A[Catch: all -> 0x014b, TryCatch #0 {all -> 0x014b, blocks: (B:43:0x0103, B:45:0x0112, B:48:0x0122, B:50:0x012f, B:52:0x0139, B:54:0x013f, B:57:0x014e, B:64:0x0164, B:67:0x016e, B:69:0x0179, B:71:0x0183, B:73:0x0189, B:74:0x0193, B:77:0x019b, B:78:0x019e, B:80:0x01a2, B:82:0x01a9, B:83:0x01b5, B:60:0x0156), top: B:91:0x0103 }] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0199  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x01a2 A[Catch: all -> 0x014b, TryCatch #0 {all -> 0x014b, blocks: (B:43:0x0103, B:45:0x0112, B:48:0x0122, B:50:0x012f, B:52:0x0139, B:54:0x013f, B:57:0x014e, B:64:0x0164, B:67:0x016e, B:69:0x0179, B:71:0x0183, B:73:0x0189, B:74:0x0193, B:77:0x019b, B:78:0x019e, B:80:0x01a2, B:82:0x01a9, B:83:0x01b5, B:60:0x0156), top: B:91:0x0103 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public androidx.compose.runtime.snapshots.r w() {
        /*
            Method dump skipped, instructions count: 449
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.C0824d.w():androidx.compose.runtime.snapshots.r");
    }

    public J x() {
        return this.h;
    }

    @Override // androidx.compose.runtime.snapshots.h
    /* renamed from: y, reason: merged with bridge method [inline-methods] */
    public Function1 e() {
        return this.e;
    }

    /* JADX WARN: Removed duplicated region for block: B:51:0x011e A[PHI: r11 r17 r24 r25
  0x011e: PHI (r11v8 java.util.ArrayList) = 
  (r11v5 java.util.ArrayList)
  (r11v5 java.util.ArrayList)
  (r11v5 java.util.ArrayList)
  (r11v6 java.util.ArrayList)
  (r11v9 java.util.ArrayList)
 binds: [B:19:0x0098, B:22:0x00a0, B:33:0x00ca, B:50:0x011b, B:14:0x0077] A[DONT_GENERATE, DONT_INLINE]
  0x011e: PHI (r17v6 int) = (r17v5 int), (r17v5 int), (r17v5 int), (r17v5 int), (r17v7 int) binds: [B:19:0x0098, B:22:0x00a0, B:33:0x00ca, B:50:0x011b, B:14:0x0077] A[DONT_GENERATE, DONT_INLINE]
  0x011e: PHI (r24v3 java.util.ArrayList) = 
  (r24v2 java.util.ArrayList)
  (r24v2 java.util.ArrayList)
  (r24v2 java.util.ArrayList)
  (r24v2 java.util.ArrayList)
  (r24v4 java.util.ArrayList)
 binds: [B:19:0x0098, B:22:0x00a0, B:33:0x00ca, B:50:0x011b, B:14:0x0077] A[DONT_GENERATE, DONT_INLINE]
  0x011e: PHI (r25v7 androidx.compose.runtime.snapshots.l) = 
  (r25v5 androidx.compose.runtime.snapshots.l)
  (r25v5 androidx.compose.runtime.snapshots.l)
  (r25v5 androidx.compose.runtime.snapshots.l)
  (r25v5 androidx.compose.runtime.snapshots.l)
  (r25v8 androidx.compose.runtime.snapshots.l)
 binds: [B:19:0x0098, B:22:0x00a0, B:33:0x00ca, B:50:0x011b, B:14:0x0077] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.compose.runtime.snapshots.r z(long r29, androidx.collection.J r31, java.util.HashMap r32, androidx.compose.runtime.snapshots.l r33) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 459
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.C0824d.z(long, androidx.collection.J, java.util.HashMap, androidx.compose.runtime.snapshots.l):androidx.compose.runtime.snapshots.r");
    }
}
