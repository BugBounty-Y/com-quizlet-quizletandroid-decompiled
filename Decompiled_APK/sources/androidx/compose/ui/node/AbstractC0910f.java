package androidx.compose.ui.node;

import android.view.View;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.ui.layout.C0893n;
import androidx.compose.ui.layout.InterfaceC0894o;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import java.util.ArrayList;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.node.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0910f {
    public static final C0908d a = new C0908d(0);

    public static final long a(float f, boolean z) {
        return ((z ? 1L : 0L) & 4294967295L) | (Float.floatToIntBits(f) << 32);
    }

    public static final void b(androidx.compose.runtime.collection.b bVar, androidx.compose.ui.p pVar) {
        androidx.compose.runtime.collection.b bVarW = v(pVar).w();
        int i = bVarW.c;
        if (i > 0) {
            int i2 = i - 1;
            Object[] objArr = bVarW.a;
            do {
                bVar.b((androidx.compose.ui.p) ((E) objArr[i2]).w.f);
                i2--;
            } while (i2 >= 0);
        }
    }

    public static final int c(O o, C0893n c0893n) {
        O oB0 = o.B0();
        if (oB0 == null) {
            W4.f("Child of " + o + " cannot be null when calculating alignment line");
            throw null;
        }
        if (o.F0().c().containsKey(c0893n)) {
            Integer num = (Integer) o.F0().c().get(c0893n);
            if (num != null) {
                return num.intValue();
            }
        } else {
            int iD0 = oB0.d0(c0893n);
            if (iD0 != Integer.MIN_VALUE) {
                oB0.g = true;
                o.h = true;
                o.J0();
                oB0.g = false;
                o.h = false;
                return c0893n instanceof C0893n ? iD0 + ((int) (oB0.H0() & 4294967295L)) : iD0 + ((int) (oB0.H0() >> 32));
            }
        }
        return Integer.MIN_VALUE;
    }

    public static final boolean d(C0907c c0907c) {
        o0 o0Var = (o0) v(c0907c).w.e;
        Intrinsics.e(o0Var, "null cannot be cast to non-null type androidx.compose.ui.node.TailModifierNode");
        return o0Var.n;
    }

    public static final androidx.compose.ui.p e(InterfaceC0917m interfaceC0917m, int i) {
        androidx.compose.ui.p pVar = ((androidx.compose.ui.p) interfaceC0917m).a.f;
        if (pVar == null || (pVar.d & i) == 0) {
            return null;
        }
        while (pVar != null) {
            int i2 = pVar.c;
            if ((i2 & 2) != 0) {
                return null;
            }
            if ((i2 & i) != 0) {
                return pVar;
            }
            pVar = pVar.f;
        }
        return null;
    }

    public static final androidx.compose.ui.p f(androidx.compose.runtime.collection.b bVar) {
        if (bVar == null || bVar.l()) {
            return null;
        }
        return (androidx.compose.ui.p) bVar.o(bVar.c - 1);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final InterfaceC0926w g(androidx.compose.ui.p pVar) {
        if ((pVar.c & 2) != 0) {
            if (pVar instanceof InterfaceC0926w) {
                return (InterfaceC0926w) pVar;
            }
            if (pVar instanceof AbstractC0918n) {
                androidx.compose.ui.p pVar2 = ((AbstractC0918n) pVar).o;
                while (pVar2 != 0) {
                    if (pVar2 instanceof InterfaceC0926w) {
                        return (InterfaceC0926w) pVar2;
                    }
                    pVar2 = (!(pVar2 instanceof AbstractC0918n) || (pVar2.c & 2) == 0) ? pVar2.f : ((AbstractC0918n) pVar2).o;
                }
            }
        }
        return null;
    }

    public static final int h(long j, long j2) {
        boolean z = ((int) (j & 4294967295L)) != 0;
        return z != (((int) (4294967295L & j2)) != 0) ? z ? -1 : 1 : (int) Math.signum(Float.intBitsToFloat((int) (j >> 32)) - Float.intBitsToFloat((int) (j2 >> 32)));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final Object i(InterfaceC0916l interfaceC0916l, AbstractC0809m0 abstractC0809m0) {
        if (!((androidx.compose.ui.p) interfaceC0916l).a.m) {
            W4.f("Cannot read CompositionLocal because the Modifier node is not currently attached.");
            throw null;
        }
        androidx.compose.runtime.internal.i iVar = (androidx.compose.runtime.internal.i) v(interfaceC0916l).u;
        iVar.getClass();
        return C0776c.B(iVar, abstractC0809m0);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v10 */
    /* JADX WARN: Type inference failed for: r2v11, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v12, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v13 */
    /* JADX WARN: Type inference failed for: r2v14 */
    /* JADX WARN: Type inference failed for: r2v15 */
    /* JADX WARN: Type inference failed for: r2v16 */
    /* JADX WARN: Type inference failed for: r2v17 */
    /* JADX WARN: Type inference failed for: r2v18 */
    /* JADX WARN: Type inference failed for: r2v7 */
    /* JADX WARN: Type inference failed for: r2v8, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r4v0 */
    /* JADX WARN: Type inference failed for: r4v1 */
    /* JADX WARN: Type inference failed for: r4v10 */
    /* JADX WARN: Type inference failed for: r4v11 */
    /* JADX WARN: Type inference failed for: r4v2 */
    /* JADX WARN: Type inference failed for: r4v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r4v4 */
    /* JADX WARN: Type inference failed for: r4v5 */
    /* JADX WARN: Type inference failed for: r4v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r4v8 */
    /* JADX WARN: Type inference failed for: r4v9 */
    public static final q0 j(InterfaceC0917m interfaceC0917m, Object obj) {
        V v;
        androidx.compose.ui.p pVar = ((androidx.compose.ui.p) interfaceC0917m).a;
        if (!pVar.m) {
            throw new IllegalStateException("visitAncestors called on an unattached node");
        }
        androidx.compose.ui.p pVar2 = pVar.e;
        E eV = v(interfaceC0917m);
        while (eV != null) {
            if ((((androidx.compose.ui.p) eV.w.f).d & 262144) != 0) {
                while (pVar2 != null) {
                    if ((pVar2.c & 262144) != 0) {
                        AbstractC0918n abstractC0918nF = pVar2;
                        ?? bVar = 0;
                        while (abstractC0918nF != 0) {
                            if (abstractC0918nF instanceof q0) {
                                q0 q0Var = (q0) abstractC0918nF;
                                if (obj.equals(q0Var.m())) {
                                    return q0Var;
                                }
                            } else if ((abstractC0918nF.c & 262144) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                androidx.compose.ui.p pVar3 = abstractC0918nF.o;
                                int i = 0;
                                abstractC0918nF = abstractC0918nF;
                                bVar = bVar;
                                while (pVar3 != null) {
                                    if ((pVar3.c & 262144) != 0) {
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
                                    abstractC0918nF = abstractC0918nF;
                                    bVar = bVar;
                                }
                                if (i == 1) {
                                }
                            }
                            abstractC0918nF = f(bVar);
                        }
                    }
                    pVar2 = pVar2.e;
                }
            }
            eV = eV.s();
            pVar2 = (eV == null || (v = eV.w) == null) ? null : (o0) v.e;
        }
        return null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v0, types: [androidx.compose.ui.node.m, androidx.compose.ui.node.q0, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r3v10 */
    /* JADX WARN: Type inference failed for: r3v11, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r3v12, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r3v13 */
    /* JADX WARN: Type inference failed for: r3v14 */
    /* JADX WARN: Type inference failed for: r3v15 */
    /* JADX WARN: Type inference failed for: r3v16 */
    /* JADX WARN: Type inference failed for: r3v17 */
    /* JADX WARN: Type inference failed for: r3v18 */
    /* JADX WARN: Type inference failed for: r3v7 */
    /* JADX WARN: Type inference failed for: r3v8, types: [androidx.compose.ui.p] */
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
    public static final q0 k(q0 q0Var) {
        V v;
        androidx.compose.ui.p pVar = ((androidx.compose.ui.p) q0Var).a;
        if (!pVar.m) {
            throw new IllegalStateException("visitAncestors called on an unattached node");
        }
        androidx.compose.ui.p pVar2 = pVar.e;
        E eV = v(q0Var);
        while (eV != null) {
            if ((((androidx.compose.ui.p) eV.w.f).d & 262144) != 0) {
                while (pVar2 != null) {
                    if ((pVar2.c & 262144) != 0) {
                        AbstractC0918n abstractC0918nF = pVar2;
                        ?? bVar = 0;
                        while (abstractC0918nF != 0) {
                            if (abstractC0918nF instanceof q0) {
                                q0 q0Var2 = (q0) abstractC0918nF;
                                if (Intrinsics.b(q0Var.m(), q0Var2.m()) && q0Var.getClass() == q0Var2.getClass()) {
                                    return q0Var2;
                                }
                            } else if ((abstractC0918nF.c & 262144) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                androidx.compose.ui.p pVar3 = abstractC0918nF.o;
                                int i = 0;
                                abstractC0918nF = abstractC0918nF;
                                bVar = bVar;
                                while (pVar3 != null) {
                                    if ((pVar3.c & 262144) != 0) {
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
                                    abstractC0918nF = abstractC0918nF;
                                    bVar = bVar;
                                }
                                if (i == 1) {
                                }
                            }
                            abstractC0918nF = f(bVar);
                        }
                    }
                    pVar2 = pVar2.e;
                }
            }
            eV = eV.s();
            pVar2 = (eV == null || (v = eV.w) == null) ? null : (o0) v.e;
        }
        return null;
    }

    public static final ArrayList l(InterfaceC0894o interfaceC0894o) {
        Intrinsics.e(interfaceC0894o, "null cannot be cast to non-null type androidx.compose.ui.node.MeasureScopeWithLayoutNode");
        E eE0 = ((O) interfaceC0894o).E0();
        boolean zQ = q(eE0);
        androidx.collection.E e = (androidx.collection.E) eE0.p();
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) e.b;
        ArrayList arrayList = new ArrayList(bVar.c);
        int i = bVar.c;
        for (int i2 = 0; i2 < i; i2++) {
            E e2 = (E) e.get(i2);
            arrayList.add(zQ ? e2.l() : e2.m());
        }
        return arrayList;
    }

    public static final int m(int[] iArr) {
        return Math.min(iArr[2] - iArr[0], iArr[3] - iArr[1]);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void n(InterfaceC0919o interfaceC0919o) {
        if (((androidx.compose.ui.p) interfaceC0919o).a.m) {
            t(interfaceC0919o, 1).c1();
        }
    }

    public static final void o(InterfaceC0926w interfaceC0926w) {
        v(interfaceC0926w).B();
    }

    public static final void p(n0 n0Var) {
        v(n0Var).C();
    }

    public static final boolean q(E e) {
        int iK = AbstractC0147y.k(e.x.c);
        if (iK == 0) {
            return false;
        }
        if (iK != 1) {
            if (iK == 2) {
                return false;
            }
            if (iK != 3) {
                if (iK != 4) {
                    throw new NoWhenBranchMatchedException();
                }
                E eS = e.s();
                if (eS != null) {
                    return q(eS);
                }
                throw new IllegalArgumentException("no parent for idle node");
            }
        }
        return true;
    }

    public static final boolean r(E e) {
        if (e.c == null) {
            return false;
        }
        E eS = e.s();
        return (eS != null ? eS.c : null) == null || e.x.b;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void s(androidx.compose.ui.p pVar, Function0 function0) {
        d0 d0Var = pVar.g;
        if (d0Var == null) {
            d0Var = new d0((c0) pVar);
            pVar.g = d0Var;
        }
        ((C0971v) w(pVar)).getSnapshotObserver().a(d0Var, C0909e.f, function0);
    }

    public static final a0 t(InterfaceC0917m interfaceC0917m, int i) {
        a0 a0Var = ((androidx.compose.ui.p) interfaceC0917m).a.h;
        Intrinsics.d(a0Var);
        if (a0Var.W0() != interfaceC0917m || !b0.h(i)) {
            return a0Var;
        }
        a0 a0Var2 = a0Var.m;
        Intrinsics.d(a0Var2);
        return a0Var2;
    }

    public static final a0 u(InterfaceC0917m interfaceC0917m) {
        if (!((androidx.compose.ui.p) interfaceC0917m).a.m) {
            W4.f("Cannot get LayoutCoordinates, Modifier.Node is not attached.");
            throw null;
        }
        a0 a0VarT = t(interfaceC0917m, 2);
        if (a0VarT.W0().m) {
            return a0VarT;
        }
        W4.f("LayoutCoordinates is not attached.");
        throw null;
    }

    public static final E v(InterfaceC0917m interfaceC0917m) {
        a0 a0Var = ((androidx.compose.ui.p) interfaceC0917m).a.h;
        if (a0Var != null) {
            return a0Var.l;
        }
        W4.g("Cannot obtain node coordinator. Is the Modifier.Node attached?");
        throw null;
    }

    public static final g0 w(InterfaceC0917m interfaceC0917m) {
        C0971v c0971v = v(interfaceC0917m).i;
        if (c0971v != null) {
            return c0971v;
        }
        W4.g("This node does not have an owner.");
        throw null;
    }

    public static final View x(InterfaceC0917m interfaceC0917m) {
        if (((androidx.compose.ui.p) interfaceC0917m).a.m) {
            return (View) H.a(v(interfaceC0917m));
        }
        W4.f("Cannot get View because the Modifier node is not currently attached.");
        throw null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r11v0, types: [kotlin.jvm.functions.Function1] */
    /* JADX WARN: Type inference failed for: r1v13 */
    /* JADX WARN: Type inference failed for: r1v14, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r1v15, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r1v16 */
    /* JADX WARN: Type inference failed for: r1v17 */
    /* JADX WARN: Type inference failed for: r1v18 */
    /* JADX WARN: Type inference failed for: r1v19 */
    /* JADX WARN: Type inference failed for: r1v20 */
    /* JADX WARN: Type inference failed for: r1v21 */
    /* JADX WARN: Type inference failed for: r1v8 */
    /* JADX WARN: Type inference failed for: r1v9, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r4v0 */
    /* JADX WARN: Type inference failed for: r4v1 */
    /* JADX WARN: Type inference failed for: r4v10 */
    /* JADX WARN: Type inference failed for: r4v11 */
    /* JADX WARN: Type inference failed for: r4v2 */
    /* JADX WARN: Type inference failed for: r4v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r4v4 */
    /* JADX WARN: Type inference failed for: r4v5 */
    /* JADX WARN: Type inference failed for: r4v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r4v8 */
    /* JADX WARN: Type inference failed for: r4v9 */
    public static final void y(androidx.compose.ui.input.pointer.h hVar, Function1 function1) {
        V v;
        androidx.compose.ui.p pVar = hVar.a;
        if (!pVar.m) {
            throw new IllegalStateException("visitAncestors called on an unattached node");
        }
        androidx.compose.ui.p pVar2 = pVar.e;
        E eV = v(hVar);
        while (eV != null) {
            if ((((androidx.compose.ui.p) eV.w.f).d & 262144) != 0) {
                while (pVar2 != null) {
                    if ((pVar2.c & 262144) != 0) {
                        AbstractC0918n abstractC0918nF = pVar2;
                        ?? bVar = 0;
                        while (abstractC0918nF != 0) {
                            boolean zBooleanValue = true;
                            if (abstractC0918nF instanceof q0) {
                                q0 q0Var = (q0) abstractC0918nF;
                                if ("androidx.compose.ui.input.pointer.PointerHoverIcon".equals(q0Var.m()) && androidx.compose.ui.input.pointer.h.class == q0Var.getClass()) {
                                    zBooleanValue = ((Boolean) function1.invoke(q0Var)).booleanValue();
                                }
                                if (!zBooleanValue) {
                                    return;
                                }
                            } else {
                                if (((abstractC0918nF.c & 262144) != 0) && (abstractC0918nF instanceof AbstractC0918n)) {
                                    androidx.compose.ui.p pVar3 = abstractC0918nF.o;
                                    int i = 0;
                                    abstractC0918nF = abstractC0918nF;
                                    bVar = bVar;
                                    while (pVar3 != null) {
                                        if ((pVar3.c & 262144) != 0) {
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
                                        abstractC0918nF = abstractC0918nF;
                                        bVar = bVar;
                                    }
                                    if (i == 1) {
                                    }
                                }
                            }
                            abstractC0918nF = f(bVar);
                        }
                    }
                    pVar2 = pVar2.e;
                }
            }
            eV = eV.s();
            pVar2 = (eV == null || (v = eV.w) == null) ? null : (o0) v.e;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r12v0, types: [androidx.compose.ui.node.q0, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r13v0, types: [kotlin.jvm.functions.Function1] */
    /* JADX WARN: Type inference failed for: r7v10, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r7v11, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r7v12 */
    /* JADX WARN: Type inference failed for: r7v13 */
    /* JADX WARN: Type inference failed for: r7v14 */
    /* JADX WARN: Type inference failed for: r7v15 */
    /* JADX WARN: Type inference failed for: r7v16 */
    /* JADX WARN: Type inference failed for: r7v17 */
    /* JADX WARN: Type inference failed for: r7v2 */
    /* JADX WARN: Type inference failed for: r7v3, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r7v9 */
    /* JADX WARN: Type inference failed for: r8v0 */
    /* JADX WARN: Type inference failed for: r8v1 */
    /* JADX WARN: Type inference failed for: r8v10 */
    /* JADX WARN: Type inference failed for: r8v11 */
    /* JADX WARN: Type inference failed for: r8v2 */
    /* JADX WARN: Type inference failed for: r8v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r8v4 */
    /* JADX WARN: Type inference failed for: r8v5 */
    /* JADX WARN: Type inference failed for: r8v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r8v8 */
    /* JADX WARN: Type inference failed for: r8v9 */
    public static final void z(q0 q0Var, Function1 function1) {
        androidx.compose.ui.p pVar = ((androidx.compose.ui.p) q0Var).a;
        if (!pVar.m) {
            W4.f("visitSubtreeIf called on an unattached node");
            throw null;
        }
        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
        androidx.compose.ui.p pVar2 = pVar.f;
        if (pVar2 == null) {
            b(bVar, pVar);
        } else {
            bVar.b(pVar2);
        }
        while (bVar.m()) {
            androidx.compose.ui.p pVar3 = (androidx.compose.ui.p) bVar.o(bVar.c - 1);
            if ((pVar3.d & 262144) != 0) {
                for (androidx.compose.ui.p pVar4 = pVar3; pVar4 != null; pVar4 = pVar4.f) {
                    if ((pVar4.c & 262144) != 0) {
                        ?? bVar2 = 0;
                        AbstractC0918n abstractC0918nF = pVar4;
                        while (abstractC0918nF != 0) {
                            if (abstractC0918nF instanceof q0) {
                                q0 q0Var2 = (q0) abstractC0918nF;
                                p0 p0Var = (Intrinsics.b(q0Var.m(), q0Var2.m()) && q0Var.getClass() == q0Var2.getClass()) ? (p0) function1.invoke(q0Var2) : p0.a;
                                if (p0Var == p0.c) {
                                    return;
                                }
                                if (p0Var == p0.b) {
                                    break;
                                }
                            } else if ((abstractC0918nF.c & 262144) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                androidx.compose.ui.p pVar5 = abstractC0918nF.o;
                                int i = 0;
                                abstractC0918nF = abstractC0918nF;
                                bVar2 = bVar2;
                                while (pVar5 != null) {
                                    if ((pVar5.c & 262144) != 0) {
                                        i++;
                                        bVar2 = bVar2;
                                        if (i == 1) {
                                            abstractC0918nF = pVar5;
                                        } else {
                                            if (bVar2 == 0) {
                                                bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                            }
                                            if (abstractC0918nF != 0) {
                                                bVar2.b(abstractC0918nF);
                                                abstractC0918nF = 0;
                                            }
                                            bVar2.b(pVar5);
                                        }
                                    }
                                    pVar5 = pVar5.f;
                                    abstractC0918nF = abstractC0918nF;
                                    bVar2 = bVar2;
                                }
                                if (i == 1) {
                                }
                            }
                            abstractC0918nF = f(bVar2);
                        }
                    }
                }
            }
            b(bVar, pVar3);
        }
    }
}
