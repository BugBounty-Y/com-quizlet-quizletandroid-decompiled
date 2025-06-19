package androidx.compose.ui.node;

import androidx.compose.animation.C0281h;
import androidx.compose.material3.F0;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.M5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.LinkedHashMap;
import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class a0 extends O implements androidx.compose.ui.layout.J, androidx.compose.ui.layout.r, h0 {
    public static final androidx.compose.ui.graphics.S F;
    public static final C0924u G;
    public static final float[] H;
    public static final C0908d I;
    public static final C0908d J;
    public boolean C;
    public f0 D;
    public androidx.compose.ui.graphics.layer.b E;
    public final E l;
    public a0 m;
    public a0 n;
    public boolean o;
    public boolean p;
    public Function1 q;
    public androidx.compose.ui.unit.b r;
    public androidx.compose.ui.unit.k s;
    public androidx.compose.ui.layout.L u;
    public LinkedHashMap v;
    public float x;
    public androidx.camera.camera2.internal.q0 y;
    public C0924u z;
    public float t = 0.8f;
    public long w = 0;
    public final C0281h A = new C0281h(this, 27);
    public final androidx.compose.ui.input.nestedscroll.b B = new androidx.compose.ui.input.nestedscroll.b(this, 7);

    static {
        androidx.compose.ui.graphics.S s = new androidx.compose.ui.graphics.S();
        s.b = 1.0f;
        s.c = 1.0f;
        s.d = 1.0f;
        long j = androidx.compose.ui.graphics.G.a;
        s.h = j;
        s.i = j;
        s.m = 8.0f;
        s.n = androidx.compose.ui.graphics.Z.b;
        s.o = androidx.compose.ui.graphics.F.a;
        s.q = 0;
        s.r = 9205357640488583168L;
        s.s = M5.b();
        s.t = androidx.compose.ui.unit.k.a;
        F = s;
        G = new C0924u();
        H = androidx.compose.ui.graphics.J.a();
        I = new C0908d(1);
        J = new C0908d(2);
    }

    public a0(E e) {
        this.l = e;
        this.r = e.r;
        this.s = e.s;
    }

    public static a0 n1(androidx.compose.ui.layout.r rVar) {
        a0 a0Var;
        androidx.compose.ui.layout.I i = rVar instanceof androidx.compose.ui.layout.I ? (androidx.compose.ui.layout.I) rVar : null;
        if (i != null && (a0Var = i.a.l) != null) {
            return a0Var;
        }
        Intrinsics.e(rVar, "null cannot be cast to non-null type androidx.compose.ui.node.NodeCoordinator");
        return (a0) rVar;
    }

    @Override // androidx.compose.ui.node.O
    public final O B0() {
        return this.m;
    }

    @Override // androidx.compose.ui.node.O
    public final androidx.compose.ui.layout.r C0() {
        return this;
    }

    @Override // androidx.compose.ui.node.O
    public final boolean D0() {
        return this.u != null;
    }

    @Override // androidx.compose.ui.layout.r
    public final long E(long j) {
        if (!W0().m) {
            W4.f("LayoutCoordinate operations are only valid when isAttached is true");
            throw null;
        }
        androidx.compose.ui.layout.r rVarG = AbstractC0897s.g(this);
        C0971v c0971v = (C0971v) H.a(this.l);
        c0971v.z();
        return e1(rVarG, androidx.compose.ui.geometry.b.g(androidx.compose.ui.graphics.J.b(j, c0971v.V), rVarG.U(0L)));
    }

    @Override // androidx.compose.ui.node.O
    public final E E0() {
        return this.l;
    }

    @Override // androidx.compose.ui.layout.r
    public final void F(androidx.compose.ui.layout.r rVar, float[] fArr) {
        a0 a0VarN1 = n1(rVar);
        a0VarN1.f1();
        a0 a0VarS0 = S0(a0VarN1);
        androidx.compose.ui.graphics.J.d(fArr);
        a0VarN1.q1(a0VarS0, fArr);
        p1(a0VarS0, fArr);
    }

    @Override // androidx.compose.ui.node.O
    public final androidx.compose.ui.layout.L F0() {
        androidx.compose.ui.layout.L l = this.u;
        if (l != null) {
            return l;
        }
        throw new IllegalStateException("Asking for measurement result of unmeasured layout modifier");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v10 */
    /* JADX WARN: Type inference failed for: r5v11 */
    /* JADX WARN: Type inference failed for: r5v12 */
    /* JADX WARN: Type inference failed for: r5v13 */
    /* JADX WARN: Type inference failed for: r5v14 */
    /* JADX WARN: Type inference failed for: r5v2 */
    /* JADX WARN: Type inference failed for: r5v3, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v6 */
    /* JADX WARN: Type inference failed for: r5v7, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v8, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r5v9 */
    /* JADX WARN: Type inference failed for: r6v0 */
    /* JADX WARN: Type inference failed for: r6v1 */
    /* JADX WARN: Type inference failed for: r6v10 */
    /* JADX WARN: Type inference failed for: r6v11 */
    /* JADX WARN: Type inference failed for: r6v2 */
    /* JADX WARN: Type inference failed for: r6v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r6v4 */
    /* JADX WARN: Type inference failed for: r6v5 */
    /* JADX WARN: Type inference failed for: r6v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r6v8 */
    /* JADX WARN: Type inference failed for: r6v9 */
    @Override // androidx.compose.ui.layout.W, androidx.compose.ui.layout.J
    public final Object G() {
        E e = this.l;
        if (!e.w.h(64)) {
            return null;
        }
        W0();
        kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
        for (androidx.compose.ui.p pVar = (o0) e.w.e; pVar != null; pVar = pVar.e) {
            if ((pVar.c & 64) != 0) {
                ?? bVar = 0;
                AbstractC0918n abstractC0918nF = pVar;
                while (abstractC0918nF != 0) {
                    if (abstractC0918nF instanceof j0) {
                        j.a = ((j0) abstractC0918nF).U(e.r, j.a);
                    } else if ((abstractC0918nF.c & 64) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                        androidx.compose.ui.p pVar2 = abstractC0918nF.o;
                        int i = 0;
                        abstractC0918nF = abstractC0918nF;
                        bVar = bVar;
                        while (pVar2 != null) {
                            if ((pVar2.c & 64) != 0) {
                                i++;
                                bVar = bVar;
                                if (i == 1) {
                                    abstractC0918nF = pVar2;
                                } else {
                                    if (bVar == 0) {
                                        bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                    }
                                    if (abstractC0918nF != 0) {
                                        bVar.b(abstractC0918nF);
                                        abstractC0918nF = 0;
                                    }
                                    bVar.b(pVar2);
                                }
                            }
                            pVar2 = pVar2.f;
                            abstractC0918nF = abstractC0918nF;
                            bVar = bVar;
                        }
                        if (i == 1) {
                        }
                    }
                    abstractC0918nF = AbstractC0910f.f(bVar);
                }
            }
        }
        return j.a;
    }

    @Override // androidx.compose.ui.node.O
    public final O G0() {
        return this.n;
    }

    @Override // androidx.compose.ui.layout.r
    public final androidx.compose.ui.layout.r H() {
        if (W0().m) {
            f1();
            return ((a0) this.l.w.d).n;
        }
        W4.f("LayoutCoordinate operations are only valid when isAttached is true");
        throw null;
    }

    @Override // androidx.compose.ui.node.O
    public final long H0() {
        return this.w;
    }

    @Override // androidx.compose.ui.node.O
    public final void J0() {
        androidx.compose.ui.graphics.layer.b bVar = this.E;
        if (bVar != null) {
            r0(this.w, this.x, bVar);
        } else {
            s0(this.w, this.x, this.q);
        }
    }

    public final void K0(a0 a0Var, androidx.camera.camera2.internal.q0 q0Var, boolean z) {
        if (a0Var == this) {
            return;
        }
        a0 a0Var2 = this.n;
        if (a0Var2 != null) {
            a0Var2.K0(a0Var, q0Var, z);
        }
        long j = this.w;
        float f = (int) (j >> 32);
        q0Var.b -= f;
        q0Var.d -= f;
        float f2 = (int) (j & 4294967295L);
        q0Var.c -= f2;
        q0Var.e -= f2;
        f0 f0Var = this.D;
        if (f0Var != null) {
            f0Var.i(q0Var, true);
            if (this.p && z) {
                long j2 = this.c;
                q0Var.e(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, (int) (j2 >> 32), (int) (j2 & 4294967295L));
            }
        }
    }

    public final long L0(a0 a0Var, long j) {
        if (a0Var == this) {
            return j;
        }
        a0 a0Var2 = this.n;
        return (a0Var2 == null || Intrinsics.b(a0Var, a0Var2)) ? T0(j) : T0(a0Var2.L0(a0Var, j));
    }

    public final long M0(long j) {
        return T4.a(Math.max(DefinitionKt.NO_Float_VALUE, (androidx.compose.ui.geometry.e.d(j) - k0()) / 2.0f), Math.max(DefinitionKt.NO_Float_VALUE, (androidx.compose.ui.geometry.e.b(j) - i0()) / 2.0f));
    }

    @Override // androidx.compose.ui.layout.r
    public final long N(long j) {
        if (W0().m) {
            return e1(AbstractC0897s.g(this), ((C0971v) H.a(this.l)).C(j));
        }
        W4.f("LayoutCoordinate operations are only valid when isAttached is true");
        throw null;
    }

    public final float N0(long j, long j2) {
        if (k0() >= androidx.compose.ui.geometry.e.d(j2) && i0() >= androidx.compose.ui.geometry.e.b(j2)) {
            return Float.POSITIVE_INFINITY;
        }
        long jM0 = M0(j2);
        float fD = androidx.compose.ui.geometry.e.d(jM0);
        float fB = androidx.compose.ui.geometry.e.b(jM0);
        float fD2 = androidx.compose.ui.geometry.b.d(j);
        float fMax = Math.max(DefinitionKt.NO_Float_VALUE, fD2 < DefinitionKt.NO_Float_VALUE ? -fD2 : fD2 - k0());
        float fE = androidx.compose.ui.geometry.b.e(j);
        long jC = Q4.c(fMax, Math.max(DefinitionKt.NO_Float_VALUE, fE < DefinitionKt.NO_Float_VALUE ? -fE : fE - i0()));
        if ((fD <= DefinitionKt.NO_Float_VALUE && fB <= DefinitionKt.NO_Float_VALUE) || androidx.compose.ui.geometry.b.d(jC) > fD || androidx.compose.ui.geometry.b.e(jC) > fB) {
            return Float.POSITIVE_INFINITY;
        }
        float fIntBitsToFloat = Float.intBitsToFloat((int) (jC >> 32));
        float fIntBitsToFloat2 = Float.intBitsToFloat((int) (jC & 4294967295L));
        return (fIntBitsToFloat2 * fIntBitsToFloat2) + (fIntBitsToFloat * fIntBitsToFloat);
    }

    public final void O0(InterfaceC0858s interfaceC0858s, androidx.compose.ui.graphics.layer.b bVar) {
        f0 f0Var = this.D;
        if (f0Var != null) {
            f0Var.g(interfaceC0858s, bVar);
            return;
        }
        long j = this.w;
        float f = (int) (j >> 32);
        float f2 = (int) (j & 4294967295L);
        interfaceC0858s.p(f, f2);
        Q0(interfaceC0858s, bVar);
        interfaceC0858s.p(-f, -f2);
    }

    public final void P0(InterfaceC0858s interfaceC0858s, com.google.android.gms.cloudmessaging.k kVar) {
        long j = this.c;
        interfaceC0858s.getClass();
        interfaceC0858s.m(0.5f, 0.5f, ((int) (j >> 32)) - 0.5f, ((int) (j & 4294967295L)) - 0.5f, kVar);
    }

    public final void Q0(InterfaceC0858s interfaceC0858s, androidx.compose.ui.graphics.layer.b bVar) {
        InterfaceC0858s interfaceC0858s2;
        androidx.compose.ui.graphics.layer.b bVar2;
        androidx.compose.ui.p pVarX0 = X0(4);
        if (pVarX0 == null) {
            i1(interfaceC0858s, bVar);
            return;
        }
        E e = this.l;
        e.getClass();
        G sharedDrawScope = ((C0971v) H.a(e)).getSharedDrawScope();
        long jF = R5.f(this.c);
        sharedDrawScope.getClass();
        androidx.compose.runtime.collection.b bVar3 = null;
        while (pVarX0 != null) {
            if (pVarX0 instanceof InterfaceC0919o) {
                interfaceC0858s2 = interfaceC0858s;
                bVar2 = bVar;
                sharedDrawScope.c(interfaceC0858s2, jF, this, (InterfaceC0919o) pVarX0, bVar2);
            } else {
                interfaceC0858s2 = interfaceC0858s;
                bVar2 = bVar;
                if ((pVarX0.c & 4) != 0 && (pVarX0 instanceof AbstractC0918n)) {
                    int i = 0;
                    for (androidx.compose.ui.p pVar = ((AbstractC0918n) pVarX0).o; pVar != null; pVar = pVar.f) {
                        if ((pVar.c & 4) != 0) {
                            i++;
                            if (i == 1) {
                                pVarX0 = pVar;
                            } else {
                                if (bVar3 == null) {
                                    bVar3 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                }
                                if (pVarX0 != null) {
                                    bVar3.b(pVarX0);
                                    pVarX0 = null;
                                }
                                bVar3.b(pVar);
                            }
                        }
                    }
                    if (i == 1) {
                    }
                }
                interfaceC0858s = interfaceC0858s2;
                bVar = bVar2;
            }
            pVarX0 = AbstractC0910f.f(bVar3);
            interfaceC0858s = interfaceC0858s2;
            bVar = bVar2;
        }
    }

    public abstract void R0();

    public final a0 S0(a0 a0Var) {
        E eS = a0Var.l;
        E e = this.l;
        if (eS == e) {
            androidx.compose.ui.p pVarW0 = a0Var.W0();
            androidx.compose.ui.p pVar = W0().a;
            if (!pVar.m) {
                W4.f("visitLocalAncestors called on an unattached node");
                throw null;
            }
            for (androidx.compose.ui.p pVar2 = pVar.e; pVar2 != null; pVar2 = pVar2.e) {
                if ((pVar2.c & 2) != 0 && pVar2 == pVarW0) {
                    return a0Var;
                }
            }
            return this;
        }
        while (eS.k > e.k) {
            eS = eS.s();
            Intrinsics.d(eS);
        }
        E eS2 = e;
        while (eS2.k > eS.k) {
            eS2 = eS2.s();
            Intrinsics.d(eS2);
        }
        while (eS != eS2) {
            eS = eS.s();
            eS2 = eS2.s();
            if (eS == null || eS2 == null) {
                throw new IllegalArgumentException("layouts are not part of the same hierarchy");
            }
        }
        if (eS2 != e) {
            if (eS != a0Var.l) {
                return (C0923t) eS.w.c;
            }
            return a0Var;
        }
        return this;
    }

    public final long T0(long j) {
        long j2 = this.w;
        long jC = Q4.c(androidx.compose.ui.geometry.b.d(j) - ((int) (j2 >> 32)), androidx.compose.ui.geometry.b.e(j) - ((int) (j2 & 4294967295L)));
        f0 f0Var = this.D;
        return f0Var != null ? f0Var.e(jC, true) : jC;
    }

    @Override // androidx.compose.ui.layout.r
    public final long U(long j) {
        if (!W0().m) {
            W4.f("LayoutCoordinate operations are only valid when isAttached is true");
            throw null;
        }
        f1();
        for (a0 a0Var = this; a0Var != null; a0Var = a0Var.n) {
            j = a0Var.o1(j);
        }
        return j;
    }

    public abstract P U0();

    public final long V0() {
        return this.r.q0(this.l.t.d());
    }

    public abstract androidx.compose.ui.p W0();

    public final androidx.compose.ui.p X0(int i) {
        boolean zH = b0.h(i);
        androidx.compose.ui.p pVarW0 = W0();
        if (!zH && (pVarW0 = pVarW0.e) == null) {
            return null;
        }
        for (androidx.compose.ui.p pVarY0 = Y0(zH); pVarY0 != null && (pVarY0.d & i) != 0; pVarY0 = pVarY0.f) {
            if ((pVarY0.c & i) != 0) {
                return pVarY0;
            }
            if (pVarY0 == pVarW0) {
                return null;
            }
        }
        return null;
    }

    public final androidx.compose.ui.p Y0(boolean z) {
        androidx.compose.ui.p pVarW0;
        V v = this.l.w;
        if (((a0) v.d) == this) {
            return (androidx.compose.ui.p) v.f;
        }
        if (!z) {
            a0 a0Var = this.n;
            if (a0Var != null) {
                return a0Var.W0();
            }
            return null;
        }
        a0 a0Var2 = this.n;
        if (a0Var2 == null || (pVarW0 = a0Var2.W0()) == null) {
            return null;
        }
        return pVarW0.f;
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.l.r.Z();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r13v10 */
    /* JADX WARN: Type inference failed for: r13v11, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r13v12, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r13v13 */
    /* JADX WARN: Type inference failed for: r13v14 */
    /* JADX WARN: Type inference failed for: r13v15 */
    /* JADX WARN: Type inference failed for: r13v16 */
    /* JADX WARN: Type inference failed for: r13v17 */
    /* JADX WARN: Type inference failed for: r13v18 */
    /* JADX WARN: Type inference failed for: r13v6 */
    /* JADX WARN: Type inference failed for: r13v7, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r1v1 */
    /* JADX WARN: Type inference failed for: r1v10 */
    /* JADX WARN: Type inference failed for: r1v11 */
    /* JADX WARN: Type inference failed for: r1v12 */
    /* JADX WARN: Type inference failed for: r1v2 */
    /* JADX WARN: Type inference failed for: r1v3 */
    /* JADX WARN: Type inference failed for: r1v4, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r1v5 */
    /* JADX WARN: Type inference failed for: r1v6 */
    /* JADX WARN: Type inference failed for: r1v7, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r1v9 */
    public final void Z0(androidx.compose.ui.p pVar, C0908d c0908d, long j, r rVar, boolean z, boolean z2) {
        if (pVar == null) {
            b1(c0908d, j, rVar, z, z2);
            return;
        }
        rVar.b(pVar, -1.0f, z2, new Y(this, pVar, c0908d, j, rVar, z, z2));
        a0 a0Var = pVar.h;
        if (a0Var != null) {
            androidx.compose.ui.p pVarY0 = a0Var.Y0(b0.h(16));
            if (pVarY0 != null && pVarY0.m) {
                androidx.compose.ui.p pVar2 = pVarY0.a;
                if (!pVar2.m) {
                    W4.f("visitLocalDescendants called on an unattached node");
                    throw null;
                }
                if ((pVar2.d & 16) != 0) {
                    while (pVar2 != null) {
                        if ((pVar2.c & 16) != 0) {
                            AbstractC0918n abstractC0918nF = pVar2;
                            ?? bVar = 0;
                            while (abstractC0918nF != 0) {
                                if (abstractC0918nF instanceof l0) {
                                    if (((l0) abstractC0918nF).p0()) {
                                        return;
                                    }
                                } else if ((abstractC0918nF.c & 16) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                    androidx.compose.ui.p pVar3 = abstractC0918nF.o;
                                    int i = 0;
                                    bVar = bVar;
                                    abstractC0918nF = abstractC0918nF;
                                    while (pVar3 != null) {
                                        if ((pVar3.c & 16) != 0) {
                                            i++;
                                            bVar = bVar;
                                            if (i == 1) {
                                                abstractC0918nF = pVar3;
                                            } else {
                                                if (bVar == 0) {
                                                    bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                }
                                                if (abstractC0918nF != 0) {
                                                    bVar.b(abstractC0918nF);
                                                    abstractC0918nF = 0;
                                                }
                                                bVar.b(pVar3);
                                            }
                                        }
                                        pVar3 = pVar3.f;
                                        bVar = bVar;
                                        abstractC0918nF = abstractC0918nF;
                                    }
                                    if (i == 1) {
                                    }
                                }
                                abstractC0918nF = AbstractC0910f.f(bVar);
                            }
                        }
                        pVar2 = pVar2.f;
                    }
                }
            }
            rVar.e = false;
        }
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.l.r.a();
    }

    /* JADX WARN: Code restructure failed: missing block: B:54:0x00de, code lost:
    
        if (androidx.compose.ui.node.AbstractC0910f.h(r18.a(), androidx.compose.ui.node.AbstractC0910f.a(r9, r20)) > 0) goto L55;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a1(androidx.compose.ui.node.C0908d r15, long r16, androidx.compose.ui.node.r r18, boolean r19, boolean r20) {
        /*
            Method dump skipped, instructions count: 256
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.a0.a1(androidx.compose.ui.node.d, long, androidx.compose.ui.node.r, boolean, boolean):void");
    }

    public void b1(C0908d c0908d, long j, r rVar, boolean z, boolean z2) {
        a0 a0Var = this.m;
        if (a0Var != null) {
            a0Var.a1(c0908d, a0Var.T0(j), rVar, z, z2);
        }
    }

    public final void c1() {
        f0 f0Var = this.D;
        if (f0Var != null) {
            f0Var.invalidate();
            return;
        }
        a0 a0Var = this.n;
        if (a0Var != null) {
            a0Var.c1();
        }
    }

    @Override // androidx.compose.ui.layout.r
    public final long d(long j) {
        long jU = U(j);
        C0971v c0971v = (C0971v) H.a(this.l);
        c0971v.z();
        return androidx.compose.ui.graphics.J.b(jU, c0971v.M);
    }

    public final boolean d1() {
        if (this.D != null && this.t <= DefinitionKt.NO_Float_VALUE) {
            return true;
        }
        a0 a0Var = this.n;
        if (a0Var != null) {
            return a0Var.d1();
        }
        return false;
    }

    public final long e1(androidx.compose.ui.layout.r rVar, long j) {
        if (rVar instanceof androidx.compose.ui.layout.I) {
            ((androidx.compose.ui.layout.I) rVar).a.l.f1();
            return ((androidx.compose.ui.layout.I) rVar).b(this, j ^ (-9223372034707292160L)) ^ (-9223372034707292160L);
        }
        a0 a0VarN1 = n1(rVar);
        a0VarN1.f1();
        a0 a0VarS0 = S0(a0VarN1);
        while (a0VarN1 != a0VarS0) {
            j = a0VarN1.o1(j);
            a0VarN1 = a0VarN1.n;
            Intrinsics.d(a0VarN1);
        }
        return L0(a0VarS0, j);
    }

    @Override // androidx.compose.ui.layout.r
    public final long f(androidx.compose.ui.layout.r rVar, long j) {
        return e1(rVar, j);
    }

    public final void f1() {
        L l = this.l.x;
        int i = l.a.x.c;
        if (i == 3 || i == 4) {
            if (l.r.x) {
                l.e(true);
            } else {
                l.d(true);
            }
        }
        if (i == 4) {
            J j = l.s;
            if (j == null || !j.u) {
                l.f(true);
            } else {
                l.g(true);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r8v10 */
    /* JADX WARN: Type inference failed for: r8v11 */
    /* JADX WARN: Type inference failed for: r8v12 */
    /* JADX WARN: Type inference failed for: r8v13 */
    /* JADX WARN: Type inference failed for: r8v14 */
    /* JADX WARN: Type inference failed for: r8v15 */
    /* JADX WARN: Type inference failed for: r8v4 */
    /* JADX WARN: Type inference failed for: r8v5, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r8v7, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r8v8 */
    /* JADX WARN: Type inference failed for: r8v9, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r9v0 */
    /* JADX WARN: Type inference failed for: r9v1 */
    /* JADX WARN: Type inference failed for: r9v10 */
    /* JADX WARN: Type inference failed for: r9v11 */
    /* JADX WARN: Type inference failed for: r9v2, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r9v3 */
    /* JADX WARN: Type inference failed for: r9v4 */
    /* JADX WARN: Type inference failed for: r9v5 */
    /* JADX WARN: Type inference failed for: r9v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r9v8 */
    /* JADX WARN: Type inference failed for: r9v9 */
    public final void g1() {
        androidx.compose.ui.p pVarW0;
        androidx.compose.ui.p pVarY0 = Y0(b0.h(128));
        if (pVarY0 == null || (pVarY0.a.d & 128) == 0) {
            return;
        }
        androidx.compose.runtime.snapshots.h hVarD = androidx.compose.runtime.snapshots.r.d();
        Function1 function1E = hVarD != null ? hVarD.e() : null;
        androidx.compose.runtime.snapshots.h hVarE = androidx.compose.runtime.snapshots.r.e(hVarD);
        try {
            boolean zH = b0.h(128);
            if (!zH) {
                pVarW0 = W0().e;
                if (pVarW0 == null) {
                }
                Unit unit = Unit.a;
                androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
            }
            pVarW0 = W0();
            for (androidx.compose.ui.p pVarY02 = Y0(zH); pVarY02 != null && (pVarY02.d & 128) != 0; pVarY02 = pVarY02.f) {
                if ((pVarY02.c & 128) != 0) {
                    ?? bVar = 0;
                    AbstractC0918n abstractC0918nF = pVarY02;
                    while (abstractC0918nF != 0) {
                        if (abstractC0918nF instanceof InterfaceC0925v) {
                            ((InterfaceC0925v) abstractC0918nF).o(this.c);
                        } else if ((abstractC0918nF.c & 128) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                            androidx.compose.ui.p pVar = abstractC0918nF.o;
                            int i = 0;
                            abstractC0918nF = abstractC0918nF;
                            bVar = bVar;
                            while (pVar != null) {
                                if ((pVar.c & 128) != 0) {
                                    i++;
                                    bVar = bVar;
                                    if (i == 1) {
                                        abstractC0918nF = pVar;
                                    } else {
                                        if (bVar == 0) {
                                            bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                        }
                                        if (abstractC0918nF != 0) {
                                            bVar.b(abstractC0918nF);
                                            abstractC0918nF = 0;
                                        }
                                        bVar.b(pVar);
                                    }
                                }
                                pVar = pVar.f;
                                abstractC0918nF = abstractC0918nF;
                                bVar = bVar;
                            }
                            if (i == 1) {
                            }
                        }
                        abstractC0918nF = AbstractC0910f.f(bVar);
                    }
                }
                if (pVarY02 == pVarW0) {
                    break;
                }
            }
            Unit unit2 = Unit.a;
            androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
        } catch (Throwable th) {
            androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
            throw th;
        }
    }

    @Override // androidx.compose.ui.layout.InterfaceC0894o
    public final androidx.compose.ui.unit.k getLayoutDirection() {
        return this.l.s;
    }

    @Override // androidx.compose.ui.layout.r
    public final androidx.compose.ui.layout.r h() {
        if (W0().m) {
            f1();
            return this.n;
        }
        W4.f("LayoutCoordinate operations are only valid when isAttached is true");
        throw null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v0 */
    /* JADX WARN: Type inference failed for: r4v1, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r4v10 */
    /* JADX WARN: Type inference failed for: r4v11 */
    /* JADX WARN: Type inference failed for: r4v3 */
    /* JADX WARN: Type inference failed for: r4v4, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r4v5, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r4v6 */
    /* JADX WARN: Type inference failed for: r4v7 */
    /* JADX WARN: Type inference failed for: r4v8 */
    /* JADX WARN: Type inference failed for: r4v9 */
    /* JADX WARN: Type inference failed for: r5v0 */
    /* JADX WARN: Type inference failed for: r5v1 */
    /* JADX WARN: Type inference failed for: r5v10 */
    /* JADX WARN: Type inference failed for: r5v11 */
    /* JADX WARN: Type inference failed for: r5v2 */
    /* JADX WARN: Type inference failed for: r5v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r5v4 */
    /* JADX WARN: Type inference failed for: r5v5 */
    /* JADX WARN: Type inference failed for: r5v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r5v8 */
    /* JADX WARN: Type inference failed for: r5v9 */
    public final void h1() {
        boolean zH = b0.h(128);
        androidx.compose.ui.p pVarW0 = W0();
        if (!zH && (pVarW0 = pVarW0.e) == null) {
            return;
        }
        for (androidx.compose.ui.p pVarY0 = Y0(zH); pVarY0 != null && (pVarY0.d & 128) != 0; pVarY0 = pVarY0.f) {
            if ((pVarY0.c & 128) != 0) {
                AbstractC0918n abstractC0918nF = pVarY0;
                ?? bVar = 0;
                while (abstractC0918nF != 0) {
                    if (abstractC0918nF instanceof InterfaceC0925v) {
                        ((InterfaceC0925v) abstractC0918nF).x(this);
                    } else if ((abstractC0918nF.c & 128) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                        androidx.compose.ui.p pVar = abstractC0918nF.o;
                        int i = 0;
                        abstractC0918nF = abstractC0918nF;
                        bVar = bVar;
                        while (pVar != null) {
                            if ((pVar.c & 128) != 0) {
                                i++;
                                bVar = bVar;
                                if (i == 1) {
                                    abstractC0918nF = pVar;
                                } else {
                                    if (bVar == 0) {
                                        bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                    }
                                    if (abstractC0918nF != 0) {
                                        bVar.b(abstractC0918nF);
                                        abstractC0918nF = 0;
                                    }
                                    bVar.b(pVar);
                                }
                            }
                            pVar = pVar.f;
                            abstractC0918nF = abstractC0918nF;
                            bVar = bVar;
                        }
                        if (i == 1) {
                        }
                    }
                    abstractC0918nF = AbstractC0910f.f(bVar);
                }
            }
            if (pVarY0 == pVarW0) {
                return;
            }
        }
    }

    public abstract void i1(InterfaceC0858s interfaceC0858s, androidx.compose.ui.graphics.layer.b bVar);

    public final void j1(long j, float f, Function1 function1, androidx.compose.ui.graphics.layer.b bVar) {
        E e = this.l;
        if (bVar == null) {
            if (this.E != null) {
                this.E = null;
                r1(null, false);
            }
            r1(function1, false);
        } else {
            if (function1 != null) {
                W4.e("both ways to create layers shouldn't be used together");
                throw null;
            }
            if (this.E != bVar) {
                this.E = null;
                r1(null, false);
                this.E = bVar;
            }
            if (this.D == null) {
                C0971v c0971v = (C0971v) H.a(e);
                C0281h c0281h = this.A;
                androidx.compose.ui.input.nestedscroll.b bVar2 = this.B;
                f0 f0VarH = c0971v.h(c0281h, bVar2, bVar);
                f0VarH.f(this.c);
                f0VarH.j(j);
                this.D = f0VarH;
                e.A = true;
                bVar2.invoke();
            }
        }
        if (!androidx.compose.ui.unit.h.b(this.w, j)) {
            this.w = j;
            e.x.r.C0();
            f0 f0Var = this.D;
            if (f0Var != null) {
                f0Var.j(j);
            } else {
                a0 a0Var = this.n;
                if (a0Var != null) {
                    a0Var.c1();
                }
            }
            O.I0(this);
            C0971v c0971v2 = e.i;
            if (c0971v2 != null) {
                c0971v2.v(e);
            }
        }
        this.x = f;
        if (this.h) {
            return;
        }
        A0(new k0(F0(), this));
    }

    @Override // androidx.compose.ui.layout.r
    public final boolean k() {
        return W0().m;
    }

    public final void k1(androidx.camera.camera2.internal.q0 q0Var, boolean z, boolean z2) {
        f0 f0Var = this.D;
        if (f0Var != null) {
            if (this.p) {
                if (z2) {
                    long jV0 = V0();
                    float fD = androidx.compose.ui.geometry.e.d(jV0) / 2.0f;
                    float fB = androidx.compose.ui.geometry.e.b(jV0) / 2.0f;
                    long j = this.c;
                    q0Var.e(-fD, -fB, ((int) (j >> 32)) + fD, ((int) (j & 4294967295L)) + fB);
                } else if (z) {
                    long j2 = this.c;
                    q0Var.e(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, (int) (j2 >> 32), (int) (j2 & 4294967295L));
                }
                if (q0Var.f()) {
                    return;
                }
            }
            f0Var.i(q0Var, false);
        }
        long j3 = this.w;
        float f = (int) (j3 >> 32);
        q0Var.b += f;
        q0Var.d += f;
        float f2 = (int) (j3 & 4294967295L);
        q0Var.c += f2;
        q0Var.e += f2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r6v0 */
    /* JADX WARN: Type inference failed for: r6v1, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r6v10 */
    /* JADX WARN: Type inference failed for: r6v11 */
    /* JADX WARN: Type inference failed for: r6v3 */
    /* JADX WARN: Type inference failed for: r6v4, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r6v5, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v6 */
    /* JADX WARN: Type inference failed for: r6v7 */
    /* JADX WARN: Type inference failed for: r6v8 */
    /* JADX WARN: Type inference failed for: r6v9 */
    /* JADX WARN: Type inference failed for: r7v0 */
    /* JADX WARN: Type inference failed for: r7v1 */
    /* JADX WARN: Type inference failed for: r7v10 */
    /* JADX WARN: Type inference failed for: r7v11 */
    /* JADX WARN: Type inference failed for: r7v2 */
    /* JADX WARN: Type inference failed for: r7v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r7v4 */
    /* JADX WARN: Type inference failed for: r7v5 */
    /* JADX WARN: Type inference failed for: r7v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r7v8 */
    /* JADX WARN: Type inference failed for: r7v9 */
    public final void l1(androidx.compose.ui.layout.L l) {
        a0 a0Var;
        androidx.compose.ui.layout.L l2 = this.u;
        if (l != l2) {
            this.u = l;
            E e = this.l;
            if (l2 == null || l.getWidth() != l2.getWidth() || l.b() != l2.b()) {
                int width = l.getWidth();
                int iB = l.b();
                f0 f0Var = this.D;
                if (f0Var != null) {
                    f0Var.f(R5.a(width, iB));
                } else if (e.F() && (a0Var = this.n) != null) {
                    a0Var.c1();
                }
                t0(R5.a(width, iB));
                if (this.q != null) {
                    s1(false);
                }
                boolean zH = b0.h(4);
                androidx.compose.ui.p pVarW0 = W0();
                if (zH || (pVarW0 = pVarW0.e) != null) {
                    for (androidx.compose.ui.p pVarY0 = Y0(zH); pVarY0 != null && (pVarY0.d & 4) != 0; pVarY0 = pVarY0.f) {
                        if ((pVarY0.c & 4) != 0) {
                            AbstractC0918n abstractC0918nF = pVarY0;
                            ?? bVar = 0;
                            while (abstractC0918nF != 0) {
                                if (abstractC0918nF instanceof InterfaceC0919o) {
                                    ((InterfaceC0919o) abstractC0918nF).M();
                                } else if ((abstractC0918nF.c & 4) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                    androidx.compose.ui.p pVar = abstractC0918nF.o;
                                    int i = 0;
                                    abstractC0918nF = abstractC0918nF;
                                    bVar = bVar;
                                    while (pVar != null) {
                                        if ((pVar.c & 4) != 0) {
                                            i++;
                                            bVar = bVar;
                                            if (i == 1) {
                                                abstractC0918nF = pVar;
                                            } else {
                                                if (bVar == 0) {
                                                    bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                }
                                                if (abstractC0918nF != 0) {
                                                    bVar.b(abstractC0918nF);
                                                    abstractC0918nF = 0;
                                                }
                                                bVar.b(pVar);
                                            }
                                        }
                                        pVar = pVar.f;
                                        abstractC0918nF = abstractC0918nF;
                                        bVar = bVar;
                                    }
                                    if (i == 1) {
                                    }
                                }
                                abstractC0918nF = AbstractC0910f.f(bVar);
                            }
                        }
                        if (pVarY0 == pVarW0) {
                            break;
                        }
                    }
                }
                C0971v c0971v = e.i;
                if (c0971v != null) {
                    c0971v.v(e);
                }
            }
            LinkedHashMap linkedHashMap = this.v;
            if (((linkedHashMap == null || linkedHashMap.isEmpty()) && l.c().isEmpty()) || Intrinsics.b(l.c(), this.v)) {
                return;
            }
            e.x.r.u.f();
            LinkedHashMap linkedHashMap2 = this.v;
            if (linkedHashMap2 == null) {
                linkedHashMap2 = new LinkedHashMap();
                this.v = linkedHashMap2;
            }
            linkedHashMap2.clear();
            linkedHashMap2.putAll(l.c());
        }
    }

    @Override // androidx.compose.ui.layout.r
    public final void m(float[] fArr) {
        g0 g0VarA = H.a(this.l);
        q1(n1(AbstractC0897s.g(this)), fArr);
        C0971v c0971v = (C0971v) g0VarA;
        c0971v.z();
        androidx.compose.ui.graphics.J.g(fArr, c0971v.M);
        float fD = androidx.compose.ui.geometry.b.d(c0971v.d1);
        float fE = androidx.compose.ui.geometry.b.e(c0971v.d1);
        float[] fArr2 = c0971v.L;
        androidx.compose.ui.graphics.J.d(fArr2);
        androidx.compose.ui.graphics.J.h(fArr2, fD, fE);
        androidx.compose.ui.platform.N.D(fArr, fArr2);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v0 */
    /* JADX WARN: Type inference failed for: r2v1, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v10 */
    /* JADX WARN: Type inference failed for: r2v11 */
    /* JADX WARN: Type inference failed for: r2v3 */
    /* JADX WARN: Type inference failed for: r2v4, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v5, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v6 */
    /* JADX WARN: Type inference failed for: r2v7 */
    /* JADX WARN: Type inference failed for: r2v8 */
    /* JADX WARN: Type inference failed for: r2v9 */
    /* JADX WARN: Type inference failed for: r3v0 */
    /* JADX WARN: Type inference failed for: r3v1 */
    /* JADX WARN: Type inference failed for: r3v10 */
    /* JADX WARN: Type inference failed for: r3v11 */
    /* JADX WARN: Type inference failed for: r3v2 */
    /* JADX WARN: Type inference failed for: r3v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r3v4 */
    /* JADX WARN: Type inference failed for: r3v5 */
    /* JADX WARN: Type inference failed for: r3v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r3v8 */
    /* JADX WARN: Type inference failed for: r3v9 */
    public final void m1(androidx.compose.ui.p pVar, C0908d c0908d, long j, r rVar, boolean z, boolean z2, float f) {
        boolean z3;
        if (pVar == null) {
            b1(c0908d, j, rVar, z, z2);
            return;
        }
        switch (c0908d.a) {
            case 1:
                AbstractC0918n abstractC0918nF = pVar;
                ?? bVar = 0;
                while (true) {
                    int i = 0;
                    if (abstractC0918nF == 0) {
                        z3 = false;
                        break;
                    } else {
                        if (abstractC0918nF instanceof l0) {
                            ((l0) abstractC0918nF).N();
                        } else if ((abstractC0918nF.c & 16) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                            androidx.compose.ui.p pVar2 = abstractC0918nF.o;
                            abstractC0918nF = abstractC0918nF;
                            bVar = bVar;
                            while (pVar2 != null) {
                                if ((pVar2.c & 16) != 0) {
                                    i++;
                                    bVar = bVar;
                                    if (i == 1) {
                                        abstractC0918nF = pVar2;
                                    } else {
                                        if (bVar == 0) {
                                            bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                        }
                                        if (abstractC0918nF != 0) {
                                            bVar.b(abstractC0918nF);
                                            abstractC0918nF = 0;
                                        }
                                        bVar.b(pVar2);
                                    }
                                }
                                pVar2 = pVar2.f;
                                abstractC0918nF = abstractC0918nF;
                                bVar = bVar;
                            }
                            if (i == 1) {
                            }
                        }
                        abstractC0918nF = AbstractC0910f.f(bVar);
                    }
                }
                break;
            default:
                z3 = false;
                break;
        }
        if (!z3) {
            m1(AbstractC0910f.e(pVar, c0908d.a()), c0908d, j, rVar, z, z2, f);
            return;
        }
        Z z4 = new Z(this, pVar, c0908d, j, rVar, z, z2, f, 1);
        if (rVar.c == kotlin.collections.B.i(rVar)) {
            rVar.b(pVar, f, z2, z4);
            if (rVar.c + 1 == kotlin.collections.B.i(rVar)) {
                rVar.e();
                return;
            }
            return;
        }
        long jA = rVar.a();
        int i2 = rVar.c;
        rVar.c = kotlin.collections.B.i(rVar);
        rVar.b(pVar, f, z2, z4);
        if (rVar.c + 1 < kotlin.collections.B.i(rVar) && AbstractC0910f.h(jA, rVar.a()) > 0) {
            int i3 = rVar.c + 1;
            int i4 = i2 + 1;
            Object[] objArr = rVar.a;
            C4930v.h(objArr, i4, objArr, i3, rVar.d);
            long[] jArr = rVar.b;
            C4930v.g(jArr, jArr, i4, i3, rVar.d);
            rVar.c = ((rVar.d + i2) - rVar.c) - 1;
        }
        rVar.e();
        rVar.c = i2;
    }

    @Override // androidx.compose.ui.layout.r
    public final androidx.compose.ui.geometry.c o(androidx.compose.ui.layout.r rVar, boolean z) {
        if (!W0().m) {
            W4.f("LayoutCoordinate operations are only valid when isAttached is true");
            throw null;
        }
        if (!rVar.k()) {
            W4.f("LayoutCoordinates " + rVar + " is not attached!");
            throw null;
        }
        a0 a0VarN1 = n1(rVar);
        a0VarN1.f1();
        a0 a0VarS0 = S0(a0VarN1);
        androidx.camera.camera2.internal.q0 q0Var = this.y;
        if (q0Var == null) {
            q0Var = new androidx.camera.camera2.internal.q0();
            q0Var.b = DefinitionKt.NO_Float_VALUE;
            q0Var.c = DefinitionKt.NO_Float_VALUE;
            q0Var.d = DefinitionKt.NO_Float_VALUE;
            q0Var.e = DefinitionKt.NO_Float_VALUE;
            this.y = q0Var;
        }
        q0Var.b = DefinitionKt.NO_Float_VALUE;
        q0Var.c = DefinitionKt.NO_Float_VALUE;
        q0Var.d = (int) (rVar.t() >> 32);
        q0Var.e = (int) (rVar.t() & 4294967295L);
        while (a0VarN1 != a0VarS0) {
            a0VarN1.k1(q0Var, z, false);
            if (q0Var.f()) {
                return androidx.compose.ui.geometry.c.e;
            }
            a0VarN1 = a0VarN1.n;
            Intrinsics.d(a0VarN1);
        }
        K0(a0VarS0, q0Var, z);
        return new androidx.compose.ui.geometry.c(q0Var.b, q0Var.c, q0Var.d, q0Var.e);
    }

    public final long o1(long j) {
        f0 f0Var = this.D;
        if (f0Var != null) {
            j = f0Var.e(j, false);
        }
        long j2 = this.w;
        return Q4.c(androidx.compose.ui.geometry.b.d(j) + ((int) (j2 >> 32)), androidx.compose.ui.geometry.b.e(j) + ((int) (j2 & 4294967295L)));
    }

    public final void p1(a0 a0Var, float[] fArr) {
        if (Intrinsics.b(a0Var, this)) {
            return;
        }
        a0 a0Var2 = this.n;
        Intrinsics.d(a0Var2);
        a0Var2.p1(a0Var, fArr);
        if (!androidx.compose.ui.unit.h.b(this.w, 0L)) {
            float[] fArr2 = H;
            androidx.compose.ui.graphics.J.d(fArr2);
            long j = this.w;
            androidx.compose.ui.graphics.J.h(fArr2, -((int) (j >> 32)), -((int) (j & 4294967295L)));
            androidx.compose.ui.graphics.J.g(fArr, fArr2);
        }
        f0 f0Var = this.D;
        if (f0Var != null) {
            f0Var.h(fArr);
        }
    }

    public final void q1(a0 a0Var, float[] fArr) {
        a0 a0Var2 = this;
        while (!a0Var2.equals(a0Var)) {
            f0 f0Var = a0Var2.D;
            if (f0Var != null) {
                f0Var.b(fArr);
            }
            if (!androidx.compose.ui.unit.h.b(a0Var2.w, 0L)) {
                float[] fArr2 = H;
                androidx.compose.ui.graphics.J.d(fArr2);
                androidx.compose.ui.graphics.J.h(fArr2, (int) (r1 >> 32), (int) (r1 & 4294967295L));
                androidx.compose.ui.graphics.J.g(fArr, fArr2);
            }
            a0Var2 = a0Var2.n;
            Intrinsics.d(a0Var2);
        }
    }

    @Override // androidx.compose.ui.layout.W
    public abstract void r0(long j, float f, androidx.compose.ui.graphics.layer.b bVar);

    public final void r1(Function1 function1, boolean z) {
        C0971v c0971v;
        if (!(function1 == null || this.E == null)) {
            W4.e("layerBlock can't be provided when explicitLayer is provided");
            throw null;
        }
        E e = this.l;
        boolean z2 = (!z && this.q == function1 && Intrinsics.b(this.r, e.r) && this.s == e.s) ? false : true;
        this.r = e.r;
        this.s = e.s;
        boolean zE = e.E();
        androidx.compose.ui.input.nestedscroll.b bVar = this.B;
        if (!zE || function1 == null) {
            this.q = null;
            f0 f0Var = this.D;
            if (f0Var != null) {
                f0Var.destroy();
                e.A = true;
                bVar.invoke();
                if (W0().m && (c0971v = e.i) != null) {
                    c0971v.v(e);
                }
            }
            this.D = null;
            this.C = false;
            return;
        }
        this.q = function1;
        if (this.D != null) {
            if (z2) {
                s1(true);
                return;
            }
            return;
        }
        f0 f0VarH = ((C0971v) H.a(e)).h(this.A, bVar, null);
        f0VarH.f(this.c);
        f0VarH.j(this.w);
        this.D = f0VarH;
        s1(true);
        e.A = true;
        bVar.invoke();
    }

    public final void s1(boolean z) {
        C0971v c0971v;
        if (this.E != null) {
            return;
        }
        f0 f0Var = this.D;
        if (f0Var == null) {
            if (this.q == null) {
                return;
            }
            W4.f("null layer with a non-null layerBlock");
            throw null;
        }
        Function1 function1 = this.q;
        if (function1 == null) {
            W4.g("updateLayerParameters requires a non-null layerBlock");
            throw null;
        }
        androidx.compose.ui.graphics.S s = F;
        s.m(1.0f);
        s.o(1.0f);
        s.b(1.0f);
        s.z(DefinitionKt.NO_Float_VALUE);
        s.B(DefinitionKt.NO_Float_VALUE);
        s.p(DefinitionKt.NO_Float_VALUE);
        long j = androidx.compose.ui.graphics.G.a;
        s.c(j);
        s.u(j);
        s.h(DefinitionKt.NO_Float_VALUE);
        s.i(DefinitionKt.NO_Float_VALUE);
        s.k(DefinitionKt.NO_Float_VALUE);
        s.d(8.0f);
        s.x(androidx.compose.ui.graphics.Z.b);
        s.t(androidx.compose.ui.graphics.F.a);
        s.e(false);
        s.f(null);
        if (s.q != 0) {
            s.a |= 32768;
            s.q = 0;
        }
        s.r = 9205357640488583168L;
        s.v = null;
        s.a = 0;
        E e = this.l;
        s.s = e.r;
        s.t = e.s;
        s.r = R5.f(this.c);
        ((C0971v) H.a(e)).getSnapshotObserver().a(this, C0909e.e, new F0(2, function1));
        C0924u c0924u = this.z;
        if (c0924u == null) {
            c0924u = new C0924u();
            this.z = c0924u;
        }
        c0924u.a = s.b;
        c0924u.b = s.c;
        c0924u.c = s.e;
        c0924u.d = s.f;
        c0924u.e = s.j;
        c0924u.f = s.k;
        c0924u.g = s.l;
        c0924u.h = s.m;
        c0924u.i = s.n;
        f0Var.d(s);
        this.p = s.p;
        this.t = s.d;
        if (!z || (c0971v = e.i) == null) {
            return;
        }
        c0971v.v(e);
    }

    @Override // androidx.compose.ui.layout.r
    public final long t() {
        return this.c;
    }

    @Override // androidx.compose.ui.node.h0
    public final boolean u() {
        return (this.D == null || this.o || !this.l.E()) ? false : true;
    }
}
