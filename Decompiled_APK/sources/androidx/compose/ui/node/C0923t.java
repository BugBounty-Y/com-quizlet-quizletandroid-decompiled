package androidx.compose.ui.node;

import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.layout.C0893n;
import androidx.compose.ui.platform.C0971v;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.ui.node.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0923t extends a0 {
    public static final com.google.android.gms.cloudmessaging.k M;
    public final o0 K;
    public C0922s L;

    static {
        com.google.android.gms.cloudmessaging.k kVarG = androidx.compose.ui.graphics.F.g();
        int i = C0861v.h;
        kVarG.f(C0861v.d);
        kVarG.l(1.0f);
        kVarG.m(1);
        M = kVarG;
    }

    public C0923t(E e) {
        super(e);
        o0 o0Var = new o0();
        o0Var.d = 0;
        this.K = o0Var;
        o0Var.h = this;
        this.L = e.c != null ? new C0922s(this) : null;
    }

    @Override // androidx.compose.ui.layout.J
    public final androidx.compose.ui.layout.W B(long j) {
        x0(j);
        E e = this.l;
        androidx.compose.runtime.collection.b bVarW = e.w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                ((E) objArr[i2]).x.r.k = 3;
                i2++;
            } while (i2 < i);
        }
        l1(e.p.mo1measure3p2s80s(this, e.m(), j));
        g1();
        return this;
    }

    @Override // androidx.compose.ui.node.a0
    public final void R0() {
        if (this.L == null) {
            this.L = new C0922s(this);
        }
    }

    @Override // androidx.compose.ui.node.a0
    public final P U0() {
        return this.L;
    }

    @Override // androidx.compose.ui.node.a0
    public final androidx.compose.ui.p W0() {
        return this.K;
    }

    @Override // androidx.compose.ui.layout.J
    public final int X(int i) {
        androidx.compose.foundation.text.input.internal.u uVarR = this.l.r();
        androidx.compose.ui.layout.K kJ = uVarR.j();
        E e = (E) uVarR.b;
        return kJ.minIntrinsicHeight((a0) e.w.d, e.m(), i);
    }

    @Override // androidx.compose.ui.layout.J
    public final int b(int i) {
        androidx.compose.foundation.text.input.internal.u uVarR = this.l.r();
        androidx.compose.ui.layout.K kJ = uVarR.j();
        E e = (E) uVarR.b;
        return kJ.maxIntrinsicHeight((a0) e.w.d, e.m(), i);
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x00b9 A[PHI: r9
  0x00b9: PHI (r9v3 androidx.compose.ui.node.r) = 
  (r9v2 androidx.compose.ui.node.r)
  (r9v4 androidx.compose.ui.node.r)
  (r9v4 androidx.compose.ui.node.r)
  (r9v4 androidx.compose.ui.node.r)
 binds: [B:37:0x006f, B:43:0x00a5, B:45:0x00ae, B:48:0x00b4] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00be A[LOOP:0: B:36:0x0067->B:52:0x00be, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00c1 A[SYNTHETIC] */
    @Override // androidx.compose.ui.node.a0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b1(androidx.compose.ui.node.C0908d r17, long r18, androidx.compose.ui.node.r r20, boolean r21, boolean r22) {
        /*
            r16 = this;
            r0 = r16
            r1 = r17
            r3 = r18
            r9 = r20
            r2 = 0
            r12 = 1
            androidx.compose.ui.node.E r5 = r0.l
            int r6 = r1.a
            switch(r6) {
                case 1: goto L20;
                default: goto L11;
            }
        L11:
            androidx.compose.ui.semantics.k r6 = r5.o()
            if (r6 == 0) goto L1d
            boolean r6 = r6.c
            if (r6 != r12) goto L1d
            r6 = r12
            goto L1e
        L1d:
            r6 = r2
        L1e:
            r6 = r6 ^ r12
            goto L21
        L20:
            r6 = r12
        L21:
            if (r6 == 0) goto L55
            boolean r6 = com.google.android.gms.internal.mlkit_vision_barcode.Q4.g(r3)
            if (r6 != 0) goto L2a
            goto L39
        L2a:
            androidx.compose.ui.node.f0 r6 = r0.D
            if (r6 == 0) goto L52
            boolean r7 = r0.p
            if (r7 == 0) goto L52
            boolean r6 = r6.c(r3)
            if (r6 == 0) goto L39
            goto L52
        L39:
            if (r21 == 0) goto L55
            long r6 = r0.V0()
            float r6 = r0.N0(r3, r6)
            boolean r7 = java.lang.Float.isInfinite(r6)
            if (r7 != 0) goto L55
            boolean r6 = java.lang.Float.isNaN(r6)
            if (r6 != 0) goto L55
            r11 = r2
        L50:
            r2 = r12
            goto L57
        L52:
            r11 = r22
            goto L50
        L55:
            r11 = r22
        L57:
            if (r2 == 0) goto Lc3
            int r13 = r9.c
            androidx.compose.runtime.collection.b r2 = r5.v()
            int r5 = r2.c
            if (r5 <= 0) goto Lc1
            int r5 = r5 - r12
            java.lang.Object[] r14 = r2.a
            r15 = r5
        L67:
            r2 = r14[r15]
            androidx.compose.ui.node.E r2 = (androidx.compose.ui.node.E) r2
            boolean r5 = r2.F()
            if (r5 == 0) goto Lb9
            int r5 = r1.a
            switch(r5) {
                case 1: goto L8e;
                default: goto L76;
            }
        L76:
            androidx.compose.ui.node.V r2 = r2.w
            java.lang.Object r5 = r2.d
            androidx.compose.ui.node.a0 r5 = (androidx.compose.ui.node.a0) r5
            long r7 = r5.T0(r3)
            java.lang.Object r2 = r2.d
            r5 = r2
            androidx.compose.ui.node.a0 r5 = (androidx.compose.ui.node.a0) r5
            androidx.compose.ui.node.d r6 = androidx.compose.ui.node.a0.J
            r10 = 1
            r5.a1(r6, r7, r9, r10, r11)
            r9 = r20
            goto L95
        L8e:
            r6 = r21
            r5 = r9
            r7 = r11
            r2.x(r3, r5, r6, r7)
        L95:
            long r2 = r9.a()
            r4 = 32
            long r4 = r2 >> r4
            int r4 = (int) r4
            float r4 = java.lang.Float.intBitsToFloat(r4)
            r5 = 0
            int r4 = (r4 > r5 ? 1 : (r4 == r5 ? 0 : -1))
            if (r4 >= 0) goto Lb9
            r4 = 4294967295(0xffffffff, double:2.1219957905E-314)
            long r2 = r2 & r4
            int r2 = (int) r2
            if (r2 == 0) goto Lb9
            boolean r2 = r9.e
            if (r2 == 0) goto Lc1
            int r2 = r9.d
            int r2 = r2 - r12
            r9.c = r2
        Lb9:
            int r15 = r15 + (-1)
            if (r15 >= 0) goto Lbe
            goto Lc1
        Lbe:
            r3 = r18
            goto L67
        Lc1:
            r9.c = r13
        Lc3:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.C0923t.b1(androidx.compose.ui.node.d, long, androidx.compose.ui.node.r, boolean, boolean):void");
    }

    @Override // androidx.compose.ui.node.a0
    public final void i1(InterfaceC0858s interfaceC0858s, androidx.compose.ui.graphics.layer.b bVar) {
        E e = this.l;
        g0 g0VarA = H.a(e);
        androidx.compose.runtime.collection.b bVarV = e.v();
        int i = bVarV.c;
        if (i > 0) {
            Object[] objArr = bVarV.a;
            int i2 = 0;
            do {
                E e2 = (E) objArr[i2];
                if (e2.F()) {
                    e2.j(interfaceC0858s, bVar);
                }
                i2++;
            } while (i2 < i);
        }
        if (((C0971v) g0VarA).getShowLayoutBounds()) {
            P0(interfaceC0858s, M);
        }
    }

    @Override // androidx.compose.ui.node.a0, androidx.compose.ui.layout.W
    public final void r0(long j, float f, androidx.compose.ui.graphics.layer.b bVar) {
        j1(j, f, null, bVar);
        if (this.g) {
            return;
        }
        h1();
        this.l.x.r.E0();
    }

    @Override // androidx.compose.ui.layout.W
    public final void s0(long j, float f, Function1 function1) {
        j1(j, f, function1, null);
        if (this.g) {
            return;
        }
        h1();
        this.l.x.r.E0();
    }

    @Override // androidx.compose.ui.layout.J
    public final int x(int i) {
        androidx.compose.foundation.text.input.internal.u uVarR = this.l.r();
        androidx.compose.ui.layout.K kJ = uVarR.j();
        E e = (E) uVarR.b;
        return kJ.minIntrinsicWidth((a0) e.w.d, e.m(), i);
    }

    @Override // androidx.compose.ui.node.O
    public final int y0(C0893n c0893n) {
        C0922s c0922s = this.L;
        if (c0922s != null) {
            return c0922s.y0(c0893n);
        }
        K k = this.l.x.r;
        boolean z = k.l;
        F f = k.u;
        if (!z) {
            L l = k.H;
            if (l.c == 1) {
                f.f = true;
                if (f.b) {
                    l.e = true;
                    l.f = true;
                }
            } else {
                f.g = true;
            }
        }
        k.e().h = true;
        k.L();
        k.e().h = false;
        Integer num = (Integer) f.i.get(c0893n);
        if (num != null) {
            return num.intValue();
        }
        return Integer.MIN_VALUE;
    }

    @Override // androidx.compose.ui.layout.J
    public final int z(int i) {
        androidx.compose.foundation.text.input.internal.u uVarR = this.l.r();
        androidx.compose.ui.layout.K kJ = uVarR.j();
        E e = (E) uVarR.b;
        return kJ.maxIntrinsicWidth((a0) e.w.d, e.m(), i);
    }
}
