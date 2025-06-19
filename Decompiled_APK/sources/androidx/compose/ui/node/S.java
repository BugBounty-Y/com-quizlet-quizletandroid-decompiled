package androidx.compose.ui.node;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class S {
    public final E a;
    public boolean c;
    public boolean d;
    public androidx.compose.ui.unit.a i;
    public final com.quizlet.data.repository.widget.b b = new com.quizlet.data.repository.widget.b(3);
    public final androidx.work.impl.model.e e = new androidx.work.impl.model.e(4);
    public final androidx.compose.runtime.collection.b f = new androidx.compose.runtime.collection.b(new E[16]);
    public final long g = 1;
    public final androidx.compose.runtime.collection.b h = new androidx.compose.runtime.collection.b(new Q[16]);

    public S(E e) {
        this.a = e;
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x0018  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean b(androidx.compose.ui.node.E r5, androidx.compose.ui.unit.a r6) {
        /*
            androidx.compose.ui.node.E r0 = r5.c
            r1 = 0
            if (r0 != 0) goto L6
            return r1
        L6:
            androidx.compose.ui.node.L r2 = r5.x
            if (r6 == 0) goto L1a
            if (r0 == 0) goto L18
            androidx.compose.ui.node.J r0 = r2.s
            kotlin.jvm.internal.Intrinsics.d(r0)
            long r2 = r6.a
            boolean r6 = r0.F0(r2)
            goto L2f
        L18:
            r6 = r1
            goto L2f
        L1a:
            androidx.compose.ui.node.J r6 = r2.s
            if (r6 == 0) goto L21
            androidx.compose.ui.unit.a r2 = r6.m
            goto L22
        L21:
            r2 = 0
        L22:
            if (r2 == 0) goto L18
            if (r0 == 0) goto L18
            kotlin.jvm.internal.Intrinsics.d(r6)
            long r2 = r2.a
            boolean r6 = r6.F0(r2)
        L2f:
            androidx.compose.ui.node.E r0 = r5.s()
            if (r6 == 0) goto L55
            if (r0 == 0) goto L55
            androidx.compose.ui.node.E r2 = r0.c
            r3 = 3
            if (r2 != 0) goto L40
            androidx.compose.ui.node.E.T(r0, r1, r3)
            return r6
        L40:
            int r2 = r5.q()
            r4 = 1
            if (r2 != r4) goto L4b
            androidx.compose.ui.node.E.R(r0, r1, r3)
            return r6
        L4b:
            int r5 = r5.q()
            r2 = 2
            if (r5 != r2) goto L55
            r0.Q(r1)
        L55:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.S.b(androidx.compose.ui.node.E, androidx.compose.ui.unit.a):boolean");
    }

    public static boolean c(E e, androidx.compose.ui.unit.a aVar) {
        boolean zL = aVar != null ? e.L(aVar) : E.M(e);
        E eS = e.s();
        if (zL && eS != null) {
            int i = e.x.r.k;
            if (i == 1) {
                E.T(eS, false, 3);
                return zL;
            }
            if (i == 2) {
                eS.S(false);
            }
        }
        return zL;
    }

    public static boolean h(E e) {
        K k = e.x.r;
        return k.k == 1 || k.u.e();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0027  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(boolean r7) {
        /*
            r6 = this;
            androidx.work.impl.model.e r0 = r6.e
            r1 = 1
            if (r7 == 0) goto L13
            java.lang.Object r7 = r0.b
            androidx.compose.runtime.collection.b r7 = (androidx.compose.runtime.collection.b) r7
            r7.i()
            androidx.compose.ui.node.E r2 = r6.a
            r7.b(r2)
            r2.F = r1
        L13:
            androidx.compose.ui.node.e0 r7 = androidx.compose.ui.node.e0.b
            java.lang.Object r2 = r0.b
            androidx.compose.runtime.collection.b r2 = (androidx.compose.runtime.collection.b) r2
            r2.s(r7)
            int r7 = r2.c
            java.lang.Object r3 = r0.c
            androidx.compose.ui.node.E[] r3 = (androidx.compose.ui.node.E[]) r3
            if (r3 == 0) goto L27
            int r4 = r3.length
            if (r4 >= r7) goto L2f
        L27:
            r3 = 16
            int r3 = java.lang.Math.max(r3, r7)
            androidx.compose.ui.node.E[] r3 = new androidx.compose.ui.node.E[r3]
        L2f:
            r4 = 0
            r0.c = r4
            r4 = 0
        L33:
            if (r4 >= r7) goto L3e
            java.lang.Object[] r5 = r2.a
            r5 = r5[r4]
            r3[r4] = r5
            int r4 = r4 + 1
            goto L33
        L3e:
            r2.i()
            int r7 = r7 - r1
        L42:
            r1 = -1
            if (r1 >= r7) goto L54
            r1 = r3[r7]
            kotlin.jvm.internal.Intrinsics.d(r1)
            boolean r2 = r1.F
            if (r2 == 0) goto L51
            androidx.work.impl.model.e.n(r1)
        L51:
            int r7 = r7 + (-1)
            goto L42
        L54:
            r0.c = r3
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.S.a(boolean):void");
    }

    public final void d() {
        androidx.compose.runtime.collection.b bVar = this.h;
        if (bVar.m()) {
            int i = bVar.c;
            if (i > 0) {
                Object[] objArr = bVar.a;
                int i2 = 0;
                do {
                    Q q = (Q) objArr[i2];
                    if (q.a.E()) {
                        boolean z = q.b;
                        boolean z2 = q.c;
                        E e = q.a;
                        if (z) {
                            E.R(e, z2, 2);
                        } else {
                            E.T(e, z2, 2);
                        }
                    }
                    i2++;
                } while (i2 < i);
            }
            bVar.i();
        }
    }

    public final void e(E e) {
        androidx.compose.runtime.collection.b bVarW = e.w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                E e2 = (E) objArr[i2];
                if (Intrinsics.b(e2.G(), Boolean.TRUE) && !e2.G) {
                    if (this.b.e(e2, true)) {
                        e2.H();
                    }
                    e(e2);
                }
                i2++;
            } while (i2 < i);
        }
    }

    public final void f(E e, boolean z) {
        com.quizlet.data.repository.widget.b bVar = this.b;
        if (((r0) ((com.quizlet.data.repository.searchexplanations.c) (z ? bVar.b : bVar.c)).c).isEmpty()) {
            return;
        }
        if (!this.c) {
            W4.f("forceMeasureTheSubtree should be executed during the measureAndLayout pass");
            throw null;
        }
        if (z ? e.x.g : e.x.d) {
            W4.e("node not yet measured");
            throw null;
        }
        g(e, z);
    }

    public final void g(E e, boolean z) {
        J j;
        F f;
        androidx.compose.runtime.collection.b bVarW = e.w();
        int i = bVarW.c;
        com.quizlet.data.repository.widget.b bVar = this.b;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                E e2 = (E) objArr[i2];
                if ((!z && h(e2)) || (z && (e2.q() == 1 || ((j = e2.x.s) != null && (f = j.r) != null && f.e())))) {
                    boolean zR = AbstractC0910f.r(e2);
                    L l = e2.x;
                    if (zR && !z) {
                        if (l.g && bVar.e(e2, true)) {
                            l(e2, true, false);
                        } else {
                            f(e2, true);
                        }
                    }
                    if ((z ? l.g : l.d) && bVar.e(e2, z)) {
                        l(e2, z, false);
                    }
                    if (!(z ? l.g : l.d)) {
                        g(e2, z);
                    }
                }
                i2++;
            } while (i2 < i);
        }
        L l2 = e.x;
        if ((z ? l2.g : l2.d) && bVar.e(e, z)) {
            l(e, z, false);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:100:0x0117 A[EDGE_INSN: B:100:0x0117->B:83:0x0117 BREAK  A[LOOP:1: B:38:0x0084->B:82:0x0114], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0114 A[LOOP:1: B:38:0x0084->B:82:0x0114, LOOP_END] */
    /* JADX WARN: Type inference failed for: r12v15 */
    /* JADX WARN: Type inference failed for: r12v5 */
    /* JADX WARN: Type inference failed for: r12v6, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v0 */
    /* JADX WARN: Type inference failed for: r5v1, types: [int] */
    /* JADX WARN: Type inference failed for: r5v2 */
    /* JADX WARN: Type inference failed for: r5v3, types: [int] */
    /* JADX WARN: Type inference failed for: r5v4 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean i(androidx.compose.ui.platform.C0965s r18) {
        /*
            Method dump skipped, instructions count: 307
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.S.i(androidx.compose.ui.platform.s):boolean");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0121 A[LOOP:0: B:38:0x009a->B:80:0x0121, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0124 A[EDGE_INSN: B:93:0x0124->B:81:0x0124 BREAK  A[LOOP:0: B:38:0x009a->B:80:0x0121], SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r11v15 */
    /* JADX WARN: Type inference failed for: r11v5 */
    /* JADX WARN: Type inference failed for: r11v6, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r17v0, types: [androidx.compose.ui.node.E, java.lang.Object] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void j(androidx.compose.ui.node.E r17, long r18) {
        /*
            Method dump skipped, instructions count: 320
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.S.j(androidx.compose.ui.node.E, long):void");
    }

    public final void k() {
        com.quizlet.data.repository.widget.b bVar = this.b;
        if (bVar.q()) {
            E e = this.a;
            if (!e.E()) {
                W4.e("performMeasureAndLayout called with unattached root");
                throw null;
            }
            if (!e.F()) {
                W4.e("performMeasureAndLayout called with unplaced root");
                throw null;
            }
            if (this.c) {
                W4.e("performMeasureAndLayout called during measure layout");
                throw null;
            }
            if (this.i != null) {
                this.c = true;
                this.d = false;
                try {
                    if (!((r0) ((com.quizlet.data.repository.searchexplanations.c) bVar.b).c).isEmpty()) {
                        if (e.c != null) {
                            n(e, true);
                        } else {
                            m(e);
                        }
                    }
                    n(e, false);
                    this.c = false;
                    this.d = false;
                } catch (Throwable th) {
                    this.c = false;
                    this.d = false;
                    throw th;
                }
            }
        }
    }

    public final boolean l(E e, boolean z, boolean z2) {
        androidx.compose.ui.unit.a aVar;
        boolean zB;
        androidx.compose.ui.layout.V placementScope;
        C0923t c0923t;
        E eS;
        J j;
        F f;
        J j2;
        F f2;
        if (!e.G) {
            boolean zF = e.F();
            L l = e.x;
            if (zF || l.r.t || ((l.d && h(e)) || Intrinsics.b(e.G(), Boolean.TRUE) || ((l.g && (e.q() == 1 || ((j2 = l.s) != null && (f2 = j2.r) != null && f2.e()))) || l.r.u.e() || ((j = l.s) != null && (f = j.r) != null && f.e())))) {
                E e2 = this.a;
                if (e == e2) {
                    aVar = this.i;
                    Intrinsics.d(aVar);
                } else {
                    aVar = null;
                }
                if (z) {
                    zB = l.g ? b(e, aVar) : false;
                    if (z2 && ((zB || l.h) && Intrinsics.b(e.G(), Boolean.TRUE))) {
                        e.H();
                    }
                } else {
                    boolean zC = l.d ? c(e, aVar) : false;
                    if (z2 && l.e && (e == e2 || ((eS = e.s()) != null && eS.F() && l.r.t))) {
                        if (e == e2) {
                            if (e.H == 3) {
                                e.g();
                            }
                            E eS2 = e.s();
                            if (eS2 == null || (c0923t = (C0923t) eS2.w.c) == null || (placementScope = c0923t.i) == null) {
                                placementScope = ((C0971v) H.a(e)).getPlacementScope();
                            }
                            androidx.compose.ui.layout.V.f(placementScope, l.r, 0, 0);
                        } else {
                            e.P();
                        }
                        ((androidx.compose.runtime.collection.b) this.e.b).b(e);
                        e.F = true;
                    }
                    zB = zC;
                }
                d();
                return zB;
            }
        }
        return false;
    }

    public final void m(E e) {
        androidx.compose.runtime.collection.b bVarW = e.w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                E e2 = (E) objArr[i2];
                if (h(e2)) {
                    if (AbstractC0910f.r(e2)) {
                        n(e2, true);
                    } else {
                        m(e2);
                    }
                }
                i2++;
            } while (i2 < i);
        }
    }

    public final void n(E e, boolean z) {
        androidx.compose.ui.unit.a aVar;
        if (e.G) {
            return;
        }
        if (e == this.a) {
            aVar = this.i;
            Intrinsics.d(aVar);
        } else {
            aVar = null;
        }
        if (z) {
            b(e, aVar);
        } else {
            c(e, aVar);
        }
    }

    public final boolean o(E e, boolean z) {
        int iK = AbstractC0147y.k(e.x.c);
        if (iK != 0 && iK != 1) {
            if (iK == 2 || iK == 3) {
                this.h.b(new Q(e, false, z));
            } else {
                if (iK != 4) {
                    throw new NoWhenBranchMatchedException();
                }
                L l = e.x;
                if (!l.d || z) {
                    l.d = true;
                    if (e.G || (!e.F() && (!l.d || !h(e)))) {
                        return false;
                    }
                    E eS = e.s();
                    if (eS == null || !eS.x.d) {
                        this.b.b(e, false);
                    }
                    if (!this.d) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public final void p(long j) {
        androidx.compose.ui.unit.a aVar = this.i;
        if (aVar == null ? false : androidx.compose.ui.unit.a.b(aVar.a, j)) {
            return;
        }
        if (this.c) {
            W4.e("updateRootConstraints called while measuring");
            throw null;
        }
        this.i = new androidx.compose.ui.unit.a(j);
        E e = this.a;
        E e2 = e.c;
        L l = e.x;
        if (e2 != null) {
            l.g = true;
        }
        l.d = true;
        this.b.b(e, e2 != null);
    }
}
