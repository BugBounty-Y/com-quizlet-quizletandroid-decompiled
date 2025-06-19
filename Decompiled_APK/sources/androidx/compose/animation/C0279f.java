package androidx.compose.animation;

import androidx.compose.animation.core.AbstractC0248j;
import androidx.compose.animation.core.C0242g;
import androidx.compose.animation.core.C0262q;
import androidx.compose.animation.core.K0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0405p0;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.layout.N0;
import androidx.compose.foundation.layout.R0;
import androidx.compose.foundation.text.J0;
import androidx.compose.foundation.text.x0;
import androidx.compose.material3.AbstractC0765y4;
import androidx.compose.material3.C0714r4;
import androidx.compose.material3.G2;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.P0;
import androidx.compose.runtime.W0;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.navigation.C1291m;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3214n5;
import com.google.android.gms.internal.mlkit_vision_barcode.F0;
import com.google.android.gms.internal.mlkit_vision_barcode.M4;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0279f extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0279f(Object obj, int i) {
        super(3);
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Type inference failed for: r9v12, types: [kotlin.jvm.functions.c, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        int i = 6;
        androidx.compose.runtime.V v = C0804k.a;
        int i2 = 0;
        Object obj4 = this.b;
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.W wB = ((androidx.compose.ui.layout.J) obj2).B(((androidx.compose.ui.unit.a) obj3).a);
                return ((androidx.compose.ui.layout.M) obj).n0(wB.a, wB.b, kotlin.collections.V.c(), new C0278e(i2, wB, (J) obj4));
            case 1:
                ((Number) obj3).intValue();
                C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
                c0814p.X(438406499);
                c0814p.p(false);
                return (K0) obj4;
            case 2:
                ((Number) obj3).intValue();
                C0814p c0814p2 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p2.X(788931215);
                C0416v0 c0416v0 = (C0416v0) obj4;
                boolean zF = c0814p2.f(c0416v0);
                Object objI = c0814p2.I();
                if (zF || objI == v) {
                    objI = new N0(c0416v0);
                    c0814p2.i0(objI);
                }
                N0 n0 = (N0) objI;
                c0814p2.p(false);
                return n0;
            case 3:
                ((Number) obj3).intValue();
                C0814p c0814p3 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p3.X(-1415685722);
                R0 r0 = (R0) obj4;
                boolean zF2 = c0814p3.f(r0);
                Object objI2 = c0814p3.I();
                if (zF2 || objI2 == v) {
                    objI2 = new C0405p0(r0);
                    c0814p3.i0(objI2);
                }
                C0405p0 c0405p0 = (C0405p0) objI2;
                c0814p3.p(false);
                return c0405p0;
            case 4:
                long j = ((androidx.compose.ui.unit.a) obj3).a;
                long j2 = ((J0) obj4).f;
                androidx.compose.ui.layout.W wB2 = ((androidx.compose.ui.layout.J) obj2).B(androidx.compose.ui.unit.a.a(j, kotlin.ranges.l.c((int) (j2 >> 32), androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.h(j)), 0, kotlin.ranges.l.c((int) (j2 & 4294967295L), androidx.compose.ui.unit.a.i(j), androidx.compose.ui.unit.a.g(j)), 0, 10));
                return ((androidx.compose.ui.layout.M) obj).n0(wB2.a, wB2.b, kotlin.collections.V.c(), new C(wB2, 10));
            case 5:
                ((Number) obj3).intValue();
                C0814p c0814p4 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p4.X(1582736677);
                androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p4.j(AbstractC0955m0.f);
                androidx.compose.ui.text.font.i iVar = (androidx.compose.ui.text.font.i) c0814p4.j(AbstractC0955m0.i);
                androidx.compose.ui.unit.k kVar = (androidx.compose.ui.unit.k) c0814p4.j(AbstractC0955m0.l);
                androidx.compose.ui.text.L l = (androidx.compose.ui.text.L) obj4;
                boolean zF3 = c0814p4.f(l) | c0814p4.f(kVar);
                Object objI3 = c0814p4.I();
                if (zF3 || objI3 == v) {
                    objI3 = AbstractC3214n5.c(l, kVar);
                    c0814p4.i0(objI3);
                }
                androidx.compose.ui.text.L l2 = (androidx.compose.ui.text.L) objI3;
                boolean zF4 = c0814p4.f(iVar) | c0814p4.f(l2);
                Object objI4 = c0814p4.I();
                if (zF4 || objI4 == v) {
                    androidx.compose.ui.text.D d = l2.a;
                    androidx.compose.ui.text.font.j jVar = d.f;
                    androidx.compose.ui.text.font.u uVar = d.c;
                    if (uVar == null) {
                        uVar = androidx.compose.ui.text.font.u.f;
                    }
                    androidx.compose.ui.text.font.q qVar = d.d;
                    int i3 = qVar != null ? qVar.a : 0;
                    androidx.compose.ui.text.font.r rVar = d.e;
                    objI4 = ((androidx.compose.ui.text.font.k) iVar).b(jVar, uVar, i3, rVar != null ? rVar.a : 1);
                    c0814p4.i0(objI4);
                }
                W0 w0 = (W0) objI4;
                Object objI5 = c0814p4.I();
                Object obj5 = objI5;
                if (objI5 == v) {
                    Object value = w0.getValue();
                    J0 j0 = new J0();
                    j0.a = kVar;
                    j0.b = bVar;
                    j0.c = iVar;
                    j0.d = l;
                    j0.e = value;
                    j0.f = x0.a(l, bVar, iVar, x0.a, 1);
                    c0814p4.i0(j0);
                    obj5 = j0;
                }
                J0 j02 = (J0) obj5;
                Object value2 = w0.getValue();
                if (kVar != j02.a || !Intrinsics.b(bVar, j02.b) || !Intrinsics.b(iVar, j02.c) || !Intrinsics.b(l2, j02.d) || !Intrinsics.b(value2, j02.e)) {
                    j02.a = kVar;
                    j02.b = bVar;
                    j02.c = iVar;
                    j02.d = l2;
                    j02.e = value2;
                    j02.f = x0.a(l2, bVar, iVar, x0.a, 1);
                }
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                boolean zH = c0814p4.h(j02);
                Object objI6 = c0814p4.I();
                if (zH || objI6 == v) {
                    objI6 = new C0279f(j02, i);
                    c0814p4.i0(objI6);
                }
                androidx.compose.ui.q qVarJ = AbstractC0897s.j(nVar, (kotlin.jvm.functions.c) objI6);
                c0814p4.p(false);
                return qVarJ;
            case 6:
                androidx.compose.ui.q qVar2 = (androidx.compose.ui.q) obj;
                ((Number) obj3).intValue();
                C0814p c0814p5 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p5.X(-1914520728);
                androidx.compose.ui.unit.b bVar2 = (androidx.compose.ui.unit.b) c0814p5.j(AbstractC0955m0.f);
                Object objI7 = c0814p5.I();
                if (objI7 == v) {
                    objI7 = C0776c.z(new androidx.compose.ui.unit.j(0L));
                    c0814p5.i0(objI7);
                }
                InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI7;
                androidx.compose.foundation.text.selection.U u = (androidx.compose.foundation.text.selection.U) obj4;
                boolean zH2 = c0814p5.h(u);
                Object objI8 = c0814p5.I();
                if (zH2 || objI8 == v) {
                    objI8 = new C0242g(8, u, interfaceC0773a0);
                    c0814p5.i0(objI8);
                }
                Function0 function0 = (Function0) objI8;
                boolean zF5 = c0814p5.f(bVar2);
                Object objI9 = c0814p5.I();
                if (zF5 || objI9 == v) {
                    objI9 = new androidx.compose.foundation.text.selection.Y(bVar2, interfaceC0773a0, i);
                    c0814p5.i0(objI9);
                }
                C0262q c0262q = androidx.compose.foundation.text.selection.O.a;
                androidx.compose.ui.q qVarA = androidx.compose.ui.a.a(qVar2, new D(i, function0, (Function1) objI9));
                c0814p5.p(false);
                return qVarA;
            case 7:
                androidx.compose.ui.q qVar3 = (androidx.compose.ui.q) obj;
                ((Number) obj3).intValue();
                C0814p c0814p6 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p6.X(1980580247);
                androidx.compose.ui.unit.b bVar3 = (androidx.compose.ui.unit.b) c0814p6.j(AbstractC0955m0.f);
                Object objI10 = c0814p6.I();
                if (objI10 == v) {
                    objI10 = C0776c.z(new androidx.compose.ui.unit.j(0L));
                    c0814p6.i0(objI10);
                }
                InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI10;
                androidx.compose.foundation.text.selection.i0 i0Var = (androidx.compose.foundation.text.selection.i0) obj4;
                boolean zH3 = c0814p6.h(i0Var);
                Object objI11 = c0814p6.I();
                if (zH3 || objI11 == v) {
                    objI11 = new C0242g(9, i0Var, interfaceC0773a02);
                    c0814p6.i0(objI11);
                }
                Function0 function02 = (Function0) objI11;
                boolean zF6 = c0814p6.f(bVar3);
                Object objI12 = c0814p6.I();
                if (zF6 || objI12 == v) {
                    objI12 = new androidx.compose.foundation.text.selection.Y(bVar3, interfaceC0773a02, 3);
                    c0814p6.i0(objI12);
                }
                C0262q c0262q2 = androidx.compose.foundation.text.selection.O.a;
                androidx.compose.ui.q qVarA2 = androidx.compose.ui.a.a(qVar3, new D(i, function02, (Function1) objI12));
                c0814p6.p(false);
                return qVarA2;
            case 8:
                androidx.compose.foundation.layout.C c = (androidx.compose.foundation.layout.C) obj;
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
                int iIntValue = ((Number) obj3).intValue();
                if ((iIntValue & 6) == 0) {
                    iIntValue |= ((C0814p) interfaceC0806l).f(c) ? 4 : 2;
                }
                C0814p c0814p7 = (C0814p) interfaceC0806l;
                if (c0814p7.N(iIntValue & 1, (iIntValue & 19) != 18)) {
                    androidx.compose.runtime.saveable.f fVarB = M4.b(c0814p7);
                    androidx.compose.material.navigation.i iVar2 = (androidx.compose.material.navigation.i) obj4;
                    InterfaceC0773a0 interfaceC0773a0M = C0776c.m(((Boolean) ((L0) iVar2.d).getValue()).booleanValue() ? iVar2.b().f : kotlinx.coroutines.flow.e0.c(kotlin.collections.M.a), c0814p7);
                    Object objC = ((Boolean) ((L0) iVar2.d).getValue()).booleanValue() ? iVar2.b().e : kotlinx.coroutines.flow.e0.c(kotlin.collections.K.a);
                    boolean zH4 = c0814p7.h(iVar2);
                    Object objI13 = c0814p7.I();
                    if (zH4 || objI13 == v) {
                        objI13 = new androidx.compose.material.navigation.h(iVar2, null);
                        c0814p7.i0(objI13);
                    }
                    Function2 function2 = (Function2) objI13;
                    Object objI14 = c0814p7.I();
                    if (objI14 == v) {
                        objI14 = C0776c.z(null);
                        c0814p7.i0(objI14);
                    }
                    InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) objI14;
                    boolean zH5 = c0814p7.h(function2);
                    Object objI15 = c0814p7.I();
                    if (zH5 || objI15 == v) {
                        objI15 = new P0(function2, interfaceC0773a03, null);
                        c0814p7.i0(objI15);
                    }
                    C0776c.f(c0814p7, objC, (Function2) objI15);
                    if (((C1291m) interfaceC0773a03.getValue()) != null) {
                        c0814p7.X(1881943300);
                        C1291m c1291m = (C1291m) interfaceC0773a03.getValue();
                        boolean zH6 = c0814p7.h(iVar2);
                        Object objI16 = c0814p7.I();
                        if (zH6 || objI16 == v) {
                            objI16 = new androidx.compose.material.navigation.c(iVar2, null);
                            c0814p7.i0(objI16);
                        }
                        C0776c.f(c0814p7, c1291m, (Function2) objI16);
                        boolean zH7 = c0814p7.h(iVar2) | c0814p7.f(interfaceC0773a03);
                        Object objI17 = c0814p7.I();
                        if (zH7 || objI17 == v) {
                            objI17 = new C0242g(12, iVar2, interfaceC0773a03);
                            c0814p7.i0(objI17);
                        }
                        androidx.work.impl.t.a(false, (Function0) objI17, c0814p7, 0, 1);
                        c0814p7.p(false);
                    } else {
                        c0814p7.X(1882110514);
                        c0814p7.p(false);
                    }
                    C1291m c1291m2 = (C1291m) interfaceC0773a03.getValue();
                    boolean zF7 = c0814p7.f(interfaceC0773a0M) | c0814p7.h(iVar2);
                    Object objI18 = c0814p7.I();
                    if (zF7 || objI18 == v) {
                        objI18 = new androidx.compose.material.navigation.d(iVar2, interfaceC0773a0M, i2);
                        c0814p7.i0(objI18);
                    }
                    Function1 function1 = (Function1) objI18;
                    boolean zF8 = c0814p7.f(interfaceC0773a0M) | c0814p7.h(iVar2);
                    Object objI19 = c0814p7.I();
                    if (zF8 || objI19 == v) {
                        objI19 = new androidx.compose.material.navigation.d(iVar2, interfaceC0773a0M, i);
                        c0814p7.i0(objI19);
                    }
                    F0.a(c, c1291m2, iVar2.c, fVarB, function1, (Function1) objI19, c0814p7, (iIntValue & 14) | com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
                } else {
                    c0814p7.Q();
                }
                return Unit.a;
            case 9:
                ((Number) obj3).intValue();
                C0814p c0814p8 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p8.X(-1541271084);
                C0714r4 c0714r4 = (C0714r4) obj4;
                float f = c0714r4.b;
                K0 k0 = AbstractC0765y4.c;
                W0 w0A = AbstractC0248j.a(f, k0, c0814p8, 0);
                W0 w0A2 = AbstractC0248j.a(c0714r4.a, k0, c0814p8, 0);
                androidx.compose.ui.q qVarS = androidx.compose.foundation.layout.K0.s(androidx.compose.foundation.layout.K0.c((androidx.compose.ui.q) obj, 1.0f), androidx.compose.ui.b.g, 2);
                boolean zF9 = c0814p8.f(w0A2);
                Object objI20 = c0814p8.I();
                if (zF9 || objI20 == v) {
                    objI20 = new G2(w0A2, i);
                    c0814p8.i0(objI20);
                }
                androidx.compose.ui.q qVarO = androidx.compose.foundation.layout.K0.o(AbstractC0382e.r(qVarS, (Function1) objI20), ((androidx.compose.ui.unit.e) w0A.getValue()).a);
                c0814p8.p(false);
                return qVarO;
            case 10:
                ((Number) obj3).intValue();
                C0814p c0814p9 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p9.X(374375707);
                Object objI21 = c0814p9.I();
                if (objI21 == v) {
                    objI21 = new androidx.compose.ui.input.pointer.r();
                    c0814p9.i0(objI21);
                }
                androidx.compose.ui.input.pointer.r rVar2 = (androidx.compose.ui.input.pointer.r) objI21;
                rVar2.b = (com.quizlet.assembly.compose.buttons.Z) obj4;
                androidx.compose.ui.input.pointer.u uVar2 = rVar2.c;
                if (uVar2 != null) {
                    uVar2.b = null;
                }
                rVar2.c = null;
                c0814p9.p(false);
                return rVar2;
            default:
                String l1 = (String) obj;
                String l22 = (String) obj2;
                grading.core.h sc = (grading.core.h) obj3;
                Intrinsics.checkNotNullParameter(l1, "l1");
                Intrinsics.checkNotNullParameter(l22, "l2");
                Intrinsics.checkNotNullParameter(sc, "sc");
                return Boolean.valueOf(!((Boolean) ((kotlin.jvm.internal.r) obj4).invoke(l1, l22, sc)).booleanValue());
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C0279f(kotlin.jvm.functions.c cVar) {
        super(3);
        this.a = 11;
        this.b = (kotlin.jvm.internal.r) cVar;
    }
}
