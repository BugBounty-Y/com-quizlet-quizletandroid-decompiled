package androidx.compose.ui.node;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.C0473q;
import androidx.compose.material3.L0;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.layout.C0893n;
import androidx.compose.ui.platform.C0971v;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class J extends androidx.compose.ui.layout.W implements androidx.compose.ui.layout.J, InterfaceC0905a, U {
    public boolean f;
    public boolean j;
    public boolean k;
    public boolean l;
    public androidx.compose.ui.unit.a m;
    public Function1 o;
    public androidx.compose.ui.graphics.layer.b p;
    public boolean q;
    public boolean u;
    public Object w;
    public boolean x;
    public final /* synthetic */ L y;
    public int g = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public int h = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public int i = 3;
    public long n = 0;
    public final F r = new F(this, 1);
    public final androidx.compose.runtime.collection.b s = new androidx.compose.runtime.collection.b(new J[16]);
    public boolean t = true;
    public boolean v = true;

    public J(L l) {
        this.y = l;
        this.w = l.r.r;
    }

    public final void A0() {
        if (this.q) {
            int i = 0;
            this.q = false;
            androidx.compose.runtime.collection.b bVarW = this.y.a.w();
            int i2 = bVarW.c;
            if (i2 > 0) {
                Object[] objArr = bVarW.a;
                do {
                    J j = ((E) objArr[i]).x.s;
                    Intrinsics.d(j);
                    j.A0();
                    i++;
                } while (i < i2);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0025  */
    @Override // androidx.compose.ui.layout.J
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.compose.ui.layout.W B(long r7) {
        /*
            r6 = this;
            androidx.compose.ui.node.L r0 = r6.y
            androidx.compose.ui.node.E r1 = r0.a
            androidx.compose.ui.node.E r1 = r1.s()
            r2 = 0
            if (r1 == 0) goto L10
            androidx.compose.ui.node.L r1 = r1.x
            int r1 = r1.c
            goto L11
        L10:
            r1 = r2
        L11:
            r3 = 2
            androidx.compose.ui.node.E r4 = r0.a
            if (r1 == r3) goto L25
            androidx.compose.ui.node.E r1 = r4.s()
            if (r1 == 0) goto L21
            androidx.compose.ui.node.L r1 = r1.x
            int r1 = r1.c
            goto L22
        L21:
            r1 = r2
        L22:
            r5 = 4
            if (r1 != r5) goto L27
        L25:
            r0.b = r2
        L27:
            androidx.compose.ui.node.E r0 = r4.s()
            r1 = 3
            if (r0 == 0) goto L66
            int r2 = r6.i
            if (r2 == r1) goto L3e
            boolean r2 = r4.v
            if (r2 == 0) goto L37
            goto L3e
        L37:
            java.lang.String r7 = "measure() may not be called multiple times on the same Measurable. If you want to get the content size of the Measurable before calculating the final constraints, please use methods like minIntrinsicWidth()/maxIntrinsicWidth() and minIntrinsicHeight()/maxIntrinsicHeight()"
            com.google.android.gms.internal.mlkit_vision_barcode.W4.f(r7)
            r7 = 0
            throw r7
        L3e:
            androidx.compose.ui.node.L r0 = r0.x
            int r2 = r0.c
            int r2 = androidx.camera.camera2.internal.AbstractC0147y.k(r2)
            r5 = 1
            if (r2 == 0) goto L62
            if (r2 == r5) goto L62
            if (r2 == r3) goto L63
            if (r2 != r1) goto L50
            goto L63
        L50:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            int r8 = r0.c
            java.lang.String r8 = androidx.compose.ui.node.B.w(r8)
            java.lang.String r0 = "Measurable could be only measured from the parent's measure or layout block. Parents state is "
            java.lang.String r8 = r0.concat(r8)
            r7.<init>(r8)
            throw r7
        L62:
            r3 = r5
        L63:
            r6.i = r3
            goto L68
        L66:
            r6.i = r1
        L68:
            int r0 = r4.H
            if (r0 != r1) goto L6f
            r4.f()
        L6f:
            r6.F0(r7)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.J.B(long):androidx.compose.ui.layout.W");
    }

    public final void B0() {
        androidx.compose.runtime.collection.b bVarW;
        int i;
        L l = this.y;
        if (l.q <= 0 || (i = (bVarW = l.a.w()).c) <= 0) {
            return;
        }
        Object[] objArr = bVarW.a;
        int i2 = 0;
        do {
            E e = (E) objArr[i2];
            L l2 = e.x;
            if ((l2.o || l2.p) && !l2.h) {
                e.Q(false);
            }
            J j = l2.s;
            if (j != null) {
                j.B0();
            }
            i2++;
        } while (i2 < i);
    }

    public final void C0() {
        int i;
        L l = this.y;
        E.R(l.a, false, 7);
        E e = l.a;
        E eS = e.s();
        if (eS == null || e.H != 3) {
            return;
        }
        int iK = AbstractC0147y.k(eS.x.c);
        if (iK != 0) {
            i = 2;
            if (iK != 2) {
                i = eS.H;
            }
        } else {
            i = 1;
        }
        e.H = i;
    }

    public final void D0() {
        L l;
        int i;
        this.x = true;
        E eS = this.y.a.s();
        if (!this.q) {
            y0();
            if (this.f && eS != null) {
                eS.Q(false);
            }
        }
        if (eS == null) {
            this.h = 0;
        } else if (!this.f && ((i = (l = eS.x).c) == 3 || i == 4)) {
            if (this.h != Integer.MAX_VALUE) {
                W4.f("Place was called on a node which was placed already");
                throw null;
            }
            int i2 = l.j;
            this.h = i2;
            l.j = i2 + 1;
        }
        L();
    }

    public final void E0(long j, Function1 function1, androidx.compose.ui.graphics.layer.b bVar) {
        L l = this.y;
        if (l.a.G) {
            W4.e("place is called on a deactivated node");
            throw null;
        }
        l.c = 4;
        this.k = true;
        this.x = false;
        if (!androidx.compose.ui.unit.h.b(j, this.n)) {
            if (l.p || l.o) {
                l.h = true;
            }
            B0();
        }
        E e = l.a;
        g0 g0VarA = H.a(e);
        if (l.h || !this.q) {
            l.f(false);
            this.r.g = false;
            i0 snapshotObserver = ((C0971v) g0VarA).getSnapshotObserver();
            I i = new I(l, g0VarA, j);
            snapshotObserver.getClass();
            if (e.c != null) {
                snapshotObserver.a(e, snapshotObserver.g, i);
            } else {
                snapshotObserver.a(e, snapshotObserver.f, i);
            }
        } else {
            P pU0 = l.a().U0();
            Intrinsics.d(pU0);
            pU0.M0(androidx.compose.ui.unit.h.d(j, pU0.e));
            D0();
        }
        this.n = j;
        this.o = function1;
        this.p = bVar;
        l.c = 5;
    }

    public final boolean F0(long j) {
        int i = 1;
        L l = this.y;
        E e = l.a;
        if (e.G) {
            W4.e("measure is called on a deactivated node");
            throw null;
        }
        E eS = e.s();
        E e2 = l.a;
        e2.v = e2.v || (eS != null && eS.v);
        if (!e2.x.g) {
            androidx.compose.ui.unit.a aVar = this.m;
            if (aVar == null ? false : androidx.compose.ui.unit.a.b(aVar.a, j)) {
                C0971v c0971v = e2.i;
                if (c0971v != null) {
                    c0971v.H.f(e2, true);
                }
                e2.V();
                return false;
            }
        }
        this.m = new androidx.compose.ui.unit.a(j);
        x0(j);
        this.r.f = false;
        androidx.compose.runtime.collection.b bVarW = e2.w();
        int i2 = bVarW.c;
        if (i2 > 0) {
            Object[] objArr = bVarW.a;
            int i3 = 0;
            do {
                J j2 = ((E) objArr[i3]).x.s;
                Intrinsics.d(j2);
                j2.r.c = false;
                Unit unit = Unit.a;
                i3++;
            } while (i3 < i2);
        }
        long jA = this.l ? this.c : R5.a(Integer.MIN_VALUE, Integer.MIN_VALUE);
        this.l = true;
        P pU0 = l.a().U0();
        if (!(pU0 != null)) {
            W4.f("Lookahead result from lookaheadRemeasure cannot be null");
            throw null;
        }
        l.c = 2;
        l.g = false;
        i0 snapshotObserver = ((C0971v) H.a(e2)).getSnapshotObserver();
        L0 l0 = new L0(l, j, i);
        snapshotObserver.getClass();
        if (e2.c != null) {
            snapshotObserver.a(e2, snapshotObserver.b, l0);
        } else {
            snapshotObserver.a(e2, snapshotObserver.c, l0);
        }
        l.h = true;
        l.i = true;
        if (AbstractC0910f.r(e2)) {
            l.e = true;
            l.f = true;
        } else {
            l.d = true;
        }
        l.c = 5;
        t0(R5.a(pU0.a, pU0.b));
        return (((int) (jA >> 32)) == pU0.a && ((int) (4294967295L & jA)) == pU0.b) ? false : true;
    }

    @Override // androidx.compose.ui.layout.W, androidx.compose.ui.layout.J
    public final Object G() {
        return this.w;
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final void L() {
        androidx.compose.runtime.collection.b bVarW;
        int i;
        this.u = true;
        F f = this.r;
        f.h();
        L l = this.y;
        boolean z = l.h;
        E e = l.a;
        if (z && (i = (bVarW = e.w()).c) > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                E e2 = (E) objArr[i2];
                if (e2.x.g && e2.q() == 1) {
                    L l2 = e2.x;
                    J j = l2.s;
                    Intrinsics.d(j);
                    J j2 = l2.s;
                    androidx.compose.ui.unit.a aVar = j2 != null ? j2.m : null;
                    Intrinsics.d(aVar);
                    if (j.F0(aVar.a)) {
                        E.R(e, false, 7);
                    }
                }
                i2++;
            } while (i2 < i);
        }
        C0922s c0922s = e().L;
        Intrinsics.d(c0922s);
        if (l.i || (!this.j && !c0922s.h && l.h)) {
            l.h = false;
            int i3 = l.c;
            l.c = 4;
            g0 g0VarA = H.a(e);
            l.g(false);
            i0 snapshotObserver = ((C0971v) g0VarA).getSnapshotObserver();
            C0473q c0473q = new C0473q(this, c0922s, l, 10);
            snapshotObserver.getClass();
            if (e.c != null) {
                snapshotObserver.a(e, snapshotObserver.h, c0473q);
            } else {
                snapshotObserver.a(e, snapshotObserver.e, c0473q);
            }
            l.c = i3;
            if (l.o && c0922s.h) {
                requestLayout();
            }
            l.i = false;
        }
        if (f.d) {
            f.e = true;
        }
        if (f.b && f.e()) {
            f.g();
        }
        this.u = false;
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final boolean M() {
        return this.q;
    }

    @Override // androidx.compose.ui.node.U
    public final void S(boolean z) {
        P pU0;
        L l = this.y;
        P pU02 = l.a().U0();
        if (Boolean.valueOf(z).equals(pU02 != null ? Boolean.valueOf(pU02.f) : null) || (pU0 = l.a().U0()) == null) {
            return;
        }
        pU0.f = z;
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final void W() {
        E.R(this.y.a, false, 7);
    }

    @Override // androidx.compose.ui.layout.J
    public final int X(int i) {
        C0();
        P pU0 = this.y.a().U0();
        Intrinsics.d(pU0);
        return pU0.X(i);
    }

    @Override // androidx.compose.ui.layout.J
    public final int b(int i) {
        C0();
        P pU0 = this.y.a().U0();
        Intrinsics.d(pU0);
        return pU0.b(i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final F c() {
        return this.r;
    }

    @Override // androidx.compose.ui.layout.W
    public final int d0(C0893n c0893n) {
        L l = this.y;
        E eS = l.a.s();
        int i = eS != null ? eS.x.c : 0;
        F f = this.r;
        if (i == 2) {
            f.c = true;
        } else {
            E eS2 = l.a.s();
            if ((eS2 != null ? eS2.x.c : 0) == 4) {
                f.d = true;
            }
        }
        this.j = true;
        P pU0 = l.a().U0();
        Intrinsics.d(pU0);
        int iD0 = pU0.d0(c0893n);
        this.j = false;
        return iD0;
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final C0923t e() {
        return (C0923t) this.y.a.w.c;
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final InterfaceC0905a i() {
        L l;
        E eS = this.y.a.s();
        if (eS == null || (l = eS.x) == null) {
            return null;
        }
        return l.s;
    }

    @Override // androidx.compose.ui.layout.W
    public final int i0() {
        P pU0 = this.y.a().U0();
        Intrinsics.d(pU0);
        return pU0.i0();
    }

    @Override // androidx.compose.ui.layout.W
    public final int k0() {
        P pU0 = this.y.a().U0();
        Intrinsics.d(pU0);
        return pU0.k0();
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final void p(C0775b0 c0775b0) {
        androidx.compose.runtime.collection.b bVarW = this.y.a.w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                J j = ((E) objArr[i2]).x.s;
                Intrinsics.d(j);
                c0775b0.invoke(j);
                i2++;
            } while (i2 < i);
        }
    }

    @Override // androidx.compose.ui.layout.W
    public final void r0(long j, float f, androidx.compose.ui.graphics.layer.b bVar) {
        E0(j, null, bVar);
    }

    @Override // androidx.compose.ui.node.InterfaceC0905a
    public final void requestLayout() {
        this.y.a.Q(false);
    }

    @Override // androidx.compose.ui.layout.W
    public final void s0(long j, float f, Function1 function1) {
        E0(j, function1, null);
    }

    @Override // androidx.compose.ui.layout.J
    public final int x(int i) {
        C0();
        P pU0 = this.y.a().U0();
        Intrinsics.d(pU0);
        return pU0.x(i);
    }

    public final void y0() {
        boolean z = this.q;
        this.q = true;
        L l = this.y;
        if (!z && l.g) {
            E.R(l.a, true, 6);
        }
        androidx.compose.runtime.collection.b bVarW = l.a.w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                E e = (E) objArr[i2];
                J j = e.x.s;
                if (j == null) {
                    throw new IllegalArgumentException("Error: Child node's lookahead pass delegate cannot be null when in a lookahead scope.");
                }
                if (j.h != Integer.MAX_VALUE) {
                    j.y0();
                    E.U(e);
                }
                i2++;
            } while (i2 < i);
        }
    }

    @Override // androidx.compose.ui.layout.J
    public final int z(int i) {
        C0();
        P pU0 = this.y.a().U0();
        Intrinsics.d(pU0);
        return pU0.z(i);
    }
}
