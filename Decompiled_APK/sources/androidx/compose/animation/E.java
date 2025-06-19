package androidx.compose.animation;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.E0;
import androidx.compose.animation.core.I0;
import androidx.compose.animation.core.J0;
import androidx.compose.animation.core.K0;
import androidx.compose.animation.core.M0;
import androidx.compose.animation.core.V0;
import androidx.compose.animation.core.w0;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.H0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.L0;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ListIterator;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class E {
    public static final void a(E0 e0, androidx.compose.ui.q qVar, Function1 function1, androidx.compose.ui.d dVar, Function1 function12, androidx.compose.runtime.internal.d dVar2, InterfaceC0806l interfaceC0806l, int i) {
        androidx.collection.I i2;
        Function1 function13;
        C0292t c0292t;
        C0814p c0814p;
        androidx.compose.runtime.snapshots.q qVar2;
        boolean z;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-114689412);
        int i3 = (i & 6) == 0 ? (c0814p2.f(e0) ? 4 : 2) | i : i;
        if ((i & 48) == 0) {
            i3 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= c0814p2.f(dVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p2.h(function12) ? 16384 : 8192;
        }
        androidx.compose.runtime.internal.d dVar3 = dVar2;
        if ((196608 & i) == 0) {
            i3 |= c0814p2.h(dVar3) ? 131072 : 65536;
        }
        if ((74899 & i3) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            function13 = function1;
            c0814p = c0814p2;
        } else {
            int i4 = i3 & 14;
            boolean z2 = i4 == 4;
            Object objI = c0814p2.I();
            Object obj = C0804k.a;
            if (z2 || objI == obj) {
                objI = new C0292t(e0, dVar);
                c0814p2.i0(objI);
            }
            C0292t c0292t2 = (C0292t) objI;
            boolean z3 = i4 == 4;
            Object objI2 = c0814p2.I();
            Object obj2 = objI2;
            if (z3 || objI2 == obj) {
                Object[] objArr = {e0.a.t()};
                androidx.compose.runtime.snapshots.q qVar3 = new androidx.compose.runtime.snapshots.q();
                qVar3.addAll(C4933y.P(objArr));
                c0814p2.i0(qVar3);
                obj2 = qVar3;
            }
            androidx.compose.runtime.snapshots.q qVar4 = (androidx.compose.runtime.snapshots.q) obj2;
            boolean z4 = i4 == 4;
            Object objI3 = c0814p2.I();
            if (z4 || objI3 == obj) {
                long[] jArr = androidx.collection.S.a;
                objI3 = new androidx.collection.I();
                c0814p2.i0(objI3);
            }
            androidx.collection.I i5 = (androidx.collection.I) objI3;
            boolean zContains = qVar4.contains(e0.a.t());
            J0 j0 = e0.a;
            if (!zContains) {
                qVar4.clear();
                qVar4.add(j0.t());
            }
            Object objT = j0.t();
            L0 l0 = (L0) e0.d;
            if (Intrinsics.b(objT, l0.getValue())) {
                if (qVar4.size() != 1 || !Intrinsics.b(qVar4.get(0), j0.t())) {
                    qVar4.clear();
                    qVar4.add(j0.t());
                }
                if (i5.e != 1 || i5.c(j0.t())) {
                    i5.a();
                }
                c0292t2.b = dVar;
            }
            if (!Intrinsics.b(j0.t(), l0.getValue()) && !qVar4.contains(l0.getValue())) {
                ListIterator listIterator = qVar4.listIterator();
                int i6 = 0;
                while (true) {
                    androidx.compose.runtime.snapshots.w wVar = (androidx.compose.runtime.snapshots.w) listIterator;
                    if (!wVar.hasNext()) {
                        i6 = -1;
                        break;
                    }
                    Object objInvoke = function12.invoke(wVar.next());
                    ListIterator listIterator2 = listIterator;
                    if (Intrinsics.b(objInvoke, function12.invoke(l0.getValue()))) {
                        break;
                    }
                    i6++;
                    listIterator = listIterator2;
                }
                if (i6 == -1) {
                    qVar4.add(l0.getValue());
                } else {
                    qVar4.set(i6, l0.getValue());
                }
            }
            if (i5.c(l0.getValue()) && i5.c(j0.t())) {
                c0814p2.X(915535767);
                c0814p2.p(false);
                i2 = i5;
                function13 = function1;
                c0292t = c0292t2;
            } else {
                c0814p2.X(912931457);
                i5.a();
                int size = qVar4.size();
                int i7 = 0;
                while (i7 < size) {
                    Object obj3 = qVar4.get(i7);
                    androidx.collection.I i8 = i5;
                    i8.j(obj3, androidx.compose.runtime.internal.e.e(885640742, new C0284k(e0, obj3, function1, c0292t2, qVar4, dVar3, 0), c0814p2));
                    i7++;
                    i5 = i8;
                    dVar3 = dVar2;
                }
                i2 = i5;
                function13 = function1;
                c0292t = c0292t2;
                c0814p2.p(false);
            }
            boolean zF = c0814p2.f(e0.f()) | c0814p2.f(c0292t);
            Object objI4 = c0814p2.I();
            if (zF || objI4 == obj) {
                objI4 = (J) function13.invoke(c0292t);
                c0814p2.i0(objI4);
            }
            J j = (J) objI4;
            c0292t.getClass();
            boolean zF2 = c0814p2.f(c0292t);
            Object objI5 = c0814p2.I();
            if (zF2 || objI5 == obj) {
                objI5 = C0776c.z(Boolean.FALSE);
                c0814p2.i0(objI5);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI5;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(j.d, c0814p2);
            E0 e02 = c0292t.a;
            if (Intrinsics.b(e02.a.t(), ((L0) e02.d).getValue())) {
                interfaceC0773a0.setValue(Boolean.FALSE);
            } else if (interfaceC0773a0D.getValue() != null) {
                interfaceC0773a0.setValue(Boolean.TRUE);
            }
            boolean zBooleanValue = ((Boolean) interfaceC0773a0.getValue()).booleanValue();
            androidx.compose.ui.q qVar5 = androidx.compose.ui.n.b;
            if (zBooleanValue) {
                c0814p2.X(249037309);
                qVar2 = qVar4;
                c0814p = c0814p2;
                w0 w0VarA = I0.a(c0292t.a, M0.h, null, c0814p, 0, 2);
                boolean zF3 = c0814p.f(w0VarA);
                Object objI6 = c0814p.I();
                if (zF3 || objI6 == obj) {
                    objI6 = androidx.compose.ui.draw.g.d(qVar5).g(new C0291s(c0292t, w0VarA, interfaceC0773a0D));
                    c0814p.i0(objI6);
                }
                qVar5 = (androidx.compose.ui.q) objI6;
                c0814p.p(false);
            } else {
                c0814p = c0814p2;
                qVar2 = qVar4;
                c0814p.X(249353726);
                c0814p.p(false);
            }
            androidx.compose.ui.q qVarG = qVar.g(qVar5);
            Object objI7 = c0814p.I();
            if (objI7 == obj) {
                objI7 = new C0288o(c0292t);
                c0814p.i0(objI7);
            }
            C0288o c0288o = (C0288o) objI7;
            int i9 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, c0288o, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i9))) {
                android.support.v4.media.session.a.z(i9, c0814p, i9, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(-1491001814);
            int size2 = qVar2.size();
            for (int i10 = 0; i10 < size2; i10++) {
                Object obj4 = qVar2.get(i10);
                c0814p.U(1908315325, function12.invoke(obj4));
                Function2 function2 = (Function2) i2.f(obj4);
                if (function2 == null) {
                    c0814p.X(-971711888);
                    z = false;
                } else {
                    z = false;
                    c0814p.X(1908317105);
                    function2.invoke(c0814p, 0);
                }
                c0814p.p(z);
                c0814p.p(z);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0285l(e0, qVar, function13, dVar, function12, dVar2, i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x005a  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x005f  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00a1  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00d8  */
    /* JADX WARN: Removed duplicated region for block: B:67:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(java.lang.Object r17, androidx.compose.ui.q r18, kotlin.jvm.functions.Function1 r19, androidx.compose.ui.i r20, java.lang.String r21, androidx.compose.animation.C0229c r22, androidx.compose.runtime.internal.d r23, androidx.compose.runtime.InterfaceC0806l r24, int r25, int r26) {
        /*
            Method dump skipped, instructions count: 230
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.E.b(java.lang.Object, androidx.compose.ui.q, kotlin.jvm.functions.Function1, androidx.compose.ui.i, java.lang.String, androidx.compose.animation.c, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int):void");
    }

    public static final void c(E0 e0, Function1 function1, androidx.compose.ui.q qVar, a0 a0Var, b0 b0Var, Function2 function2, kotlin.jvm.functions.c cVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        int i3;
        a0 a0Var2;
        E0 e02;
        w0 w0Var;
        w0 w0Var2;
        w0 w0Var3;
        boolean z;
        w0 w0VarA;
        b0 b0Var2;
        boolean z2;
        kotlin.jvm.functions.c cVar2;
        kotlin.jvm.functions.c cVar3;
        kotlin.jvm.functions.c cVar4 = cVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-891967166);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(e0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(a0Var) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(b0Var) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function2) ? 131072 : 65536;
        }
        int i4 = i2 | 1572864;
        if ((12582912 & i) == 0) {
            i4 |= c0814p.h(cVar4) ? 8388608 : 4194304;
        }
        int i5 = i4;
        if ((i5 & 4793491) == 4793490 && c0814p.x()) {
            c0814p.Q();
            cVar3 = cVar4;
        } else {
            boolean zBooleanValue = ((Boolean) function1.invoke(((L0) e0.d).getValue())).booleanValue();
            J0 j0 = e0.a;
            if (zBooleanValue || ((Boolean) function1.invoke(j0.t())).booleanValue() || e0.h() || e0.d()) {
                c0814p.X(1787977937);
                int i6 = i5 & 14;
                int i7 = i6 | 48;
                int i8 = i7 & 14;
                boolean z3 = ((i8 ^ 6) > 4 && c0814p.f(e0)) || (i7 & 6) == 4;
                Object objI = c0814p.I();
                androidx.compose.runtime.V v = C0804k.a;
                if (z3 || objI == v) {
                    objI = j0.t();
                    c0814p.i0(objI);
                }
                if (e0.h()) {
                    objI = j0.t();
                }
                c0814p.X(-466616829);
                O oK = k(e0, function1, objI, c0814p);
                c0814p.p(false);
                Object value = ((L0) e0.d).getValue();
                c0814p.X(-466616829);
                O oK2 = k(e0, function1, value, c0814p);
                c0814p.p(false);
                int i9 = i8 | 3072;
                Object obj = I0.a;
                int i10 = (i9 & 14) ^ 6;
                boolean z4 = (i10 > 4 && c0814p.f(e0)) || (i9 & 6) == 4;
                Object objI2 = c0814p.I();
                if (z4 || objI2 == v) {
                    i3 = i9;
                    objI2 = new E0(new androidx.compose.animation.core.T(oK), e0, android.support.v4.media.session.a.t(new StringBuilder(), e0.c, " > EnterExitTransition"));
                    c0814p.i0(objI2);
                } else {
                    i3 = i9;
                }
                E0 e03 = (E0) objI2;
                boolean zF = ((i10 > 4 && c0814p.f(e0)) || (i3 & 6) == 4) | c0814p.f(e03);
                Object objI3 = c0814p.I();
                if (zF || objI3 == v) {
                    objI3 = new C0278e(4, e0, e03);
                    c0814p.i0(objI3);
                }
                C0776c.d(e03, (Function1) objI3, c0814p);
                if (e0.h()) {
                    e03.m(oK, oK2);
                } else {
                    e03.r(oK2);
                    ((L0) e03.k).setValue(Boolean.FALSE);
                }
                InterfaceC0773a0 interfaceC0773a0D = C0776c.D(function2, c0814p);
                Object objT = e03.a.t();
                InterfaceC0773a0 interfaceC0773a0 = e03.d;
                Object objInvoke = function2.invoke(objT, ((L0) interfaceC0773a0).getValue());
                boolean zF2 = c0814p.f(e03) | c0814p.f(interfaceC0773a0D);
                Object objI4 = c0814p.I();
                if (zF2 || objI4 == v) {
                    objI4 = new C0298z(e03, interfaceC0773a0D, null);
                    c0814p.i0(objI4);
                }
                InterfaceC0773a0 interfaceC0773a0A = C0776c.A(c0814p, objInvoke, (Function2) objI4);
                J0 j02 = e03.a;
                Object objT2 = j02.t();
                O o = O.c;
                if (objT2 == o && ((L0) interfaceC0773a0).getValue() == o && ((Boolean) interfaceC0773a0A.getValue()).booleanValue()) {
                    c0814p.X(1790256282);
                    c0814p.p(false);
                    cVar2 = cVar;
                    z2 = false;
                } else {
                    c0814p.X(1788869559);
                    boolean z5 = i6 == 4;
                    Object objI5 = c0814p.I();
                    if (z5 || objI5 == v) {
                        objI5 = new G();
                        c0814p.i0(objI5);
                    }
                    G g = (G) objI5;
                    androidx.compose.animation.core.L0 l0 = V.a;
                    S s = S.a;
                    boolean zF3 = c0814p.f(e03);
                    Object objI6 = c0814p.I();
                    if (zF3 || objI6 == v) {
                        objI6 = C0776c.z(a0Var);
                        c0814p.i0(objI6);
                    }
                    InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI6;
                    Object objT3 = j02.t();
                    L0 l02 = (L0) interfaceC0773a0;
                    Object value2 = l02.getValue();
                    O o2 = O.b;
                    if (objT3 == value2 && j02.t() == o2) {
                        if (e03.h()) {
                            interfaceC0773a02.setValue(a0Var);
                        } else {
                            interfaceC0773a02.setValue(a0.b);
                        }
                    } else if (l02.getValue() == o2) {
                        interfaceC0773a02.setValue(((a0) interfaceC0773a02.getValue()).a(a0Var));
                    }
                    a0 a0Var3 = (a0) interfaceC0773a02.getValue();
                    boolean zF4 = c0814p.f(e03);
                    Object objI7 = c0814p.I();
                    if (zF4 || objI7 == v) {
                        objI7 = C0776c.z(b0Var);
                        c0814p.i0(objI7);
                    }
                    InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) objI7;
                    if (j02.t() == l02.getValue() && j02.t() == o2) {
                        if (e03.h()) {
                            interfaceC0773a03.setValue(b0Var);
                        } else {
                            interfaceC0773a03.setValue(b0.b);
                        }
                    } else if (l02.getValue() != o2) {
                        interfaceC0773a03.setValue(((b0) interfaceC0773a03.getValue()).a(b0Var));
                    }
                    b0 b0Var3 = (b0) interfaceC0773a03.getValue();
                    q0 q0Var = a0Var3.a;
                    boolean z6 = (q0Var.b == null && b0Var3.a.b == null) ? false : true;
                    boolean z7 = (q0Var.c == null && b0Var3.a.c == null) ? false : true;
                    if (z6) {
                        c0814p.X(-821375963);
                        androidx.compose.animation.core.L0 l03 = M0.g;
                        Object objI8 = c0814p.I();
                        if (objI8 == v) {
                            objI8 = "Built-in slide";
                            c0814p.i0("Built-in slide");
                        }
                        String str = (String) objI8;
                        a0Var2 = a0Var3;
                        e02 = e03;
                        w0 w0VarA2 = I0.a(e02, l03, str, c0814p, 384, 0);
                        c0814p.p(false);
                        w0Var = w0VarA2;
                    } else {
                        a0Var2 = a0Var3;
                        e02 = e03;
                        c0814p.X(-821278096);
                        c0814p.p(false);
                        w0Var = null;
                    }
                    if (z7) {
                        c0814p.X(-821202177);
                        androidx.compose.animation.core.L0 l04 = M0.h;
                        Object objI9 = c0814p.I();
                        if (objI9 == v) {
                            objI9 = "Built-in shrink/expand";
                            c0814p.i0("Built-in shrink/expand");
                        }
                        w0 w0VarA3 = I0.a(e02, l04, (String) objI9, c0814p, 384, 0);
                        c0814p.p(false);
                        w0Var2 = w0VarA3;
                    } else {
                        c0814p.X(-821099041);
                        c0814p.p(false);
                        w0Var2 = null;
                    }
                    if (z7) {
                        c0814p.X(-821034002);
                        androidx.compose.animation.core.L0 l05 = M0.g;
                        Object objI10 = c0814p.I();
                        if (objI10 == v) {
                            objI10 = "Built-in InterruptionHandlingOffset";
                            c0814p.i0("Built-in InterruptionHandlingOffset");
                        }
                        w0 w0VarA4 = I0.a(e02, l05, (String) objI10, c0814p, 384, 0);
                        c0814p.p(false);
                        w0Var3 = w0VarA4;
                    } else {
                        c0814p.X(-820883777);
                        c0814p.p(false);
                        w0Var3 = null;
                    }
                    boolean z8 = !z7;
                    if ((a0Var2.a.a == null && b0Var3.a.a == null) ? false : true) {
                        c0814p.X(-675389204);
                        androidx.compose.animation.core.L0 l06 = M0.a;
                        Object objI11 = c0814p.I();
                        if (objI11 == v) {
                            objI11 = "Built-in alpha";
                            c0814p.i0("Built-in alpha");
                        }
                        w0VarA = I0.a(e02, l06, (String) objI11, c0814p, 384, 0);
                        z = false;
                        c0814p.p(false);
                    } else {
                        z = false;
                        c0814p.X(-675252433);
                        c0814p.p(false);
                        w0VarA = null;
                    }
                    c0814p.X(-675057009);
                    c0814p.p(z);
                    c0814p.X(-674835793);
                    c0814p.p(z);
                    w0 w0Var4 = null;
                    boolean zH = c0814p.h(w0VarA) | c0814p.f(a0Var2) | c0814p.f(b0Var3) | c0814p.h(null) | c0814p.f(e02) | c0814p.h(null);
                    Object objI12 = c0814p.I();
                    if (zH || objI12 == v) {
                        b0Var2 = b0Var3;
                        objI12 = new P(w0VarA, w0Var4, e02, a0Var2, b0Var2, w0Var4);
                        c0814p.i0(objI12);
                    } else {
                        b0Var2 = b0Var3;
                    }
                    P p = (P) objI12;
                    androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                    boolean zG = c0814p.g(z8) | c0814p.f(s);
                    Object objI13 = c0814p.I();
                    if (zG || objI13 == v) {
                        objI13 = new T(z8, s, 0);
                        c0814p.i0(objI13);
                    }
                    androidx.compose.ui.q qVarG = androidx.compose.ui.graphics.F.p(nVar, (Function1) objI13).g(new EnterExitTransitionElement(e02, w0Var2, w0Var3, w0Var, a0Var2, b0Var2, s, p));
                    c0814p.X(1581766416);
                    c0814p.p(false);
                    androidx.compose.ui.q qVarG2 = qVar.g(qVarG.g(nVar));
                    Object objI14 = c0814p.I();
                    if (objI14 == v) {
                        objI14 = new C0294v(g);
                        c0814p.i0(objI14);
                    }
                    C0294v c0294v = (C0294v) objI14;
                    int i11 = c0814p.P;
                    InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
                    androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG2);
                    InterfaceC0915k.D0.getClass();
                    C0913i c0913i = C0914j.b;
                    c0814p.b0();
                    if (c0814p.O) {
                        c0814p.k(c0913i);
                    } else {
                        c0814p.l0();
                    }
                    C0776c.E(c0814p, c0294v, C0914j.f);
                    C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
                    C0912h c0912h = C0914j.g;
                    if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i11))) {
                        android.support.v4.media.session.a.z(i11, c0814p, i11, c0912h);
                    }
                    C0776c.E(c0814p, qVarC, C0914j.d);
                    kotlin.jvm.functions.c cVar5 = cVar;
                    cVar5.invoke(g, c0814p, Integer.valueOf((i5 >> 18) & ContentType.LONG_FORM_ON_DEMAND));
                    c0814p.p(true);
                    z2 = false;
                    c0814p.p(false);
                    cVar2 = cVar5;
                }
                c0814p.p(z2);
                cVar3 = cVar2;
            } else {
                c0814p.X(1790262234);
                c0814p.p(false);
                cVar3 = cVar4;
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0295w(e0, function1, qVar, a0Var, b0Var, function2, cVar3, i);
        }
    }

    public static final void d(androidx.compose.animation.core.T t, androidx.compose.ui.q qVar, a0 a0Var, b0 b0Var, String str, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        b0 b0Var2;
        String str2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-222898426);
        int i2 = i | (c0814p.f(t) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.f(a0Var) ? 256 : 128) | 27648;
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
            b0Var2 = b0Var;
            str2 = str;
        } else {
            b0 b0VarD = V.d(null, 3);
            Object obj = V0.a;
            b0 b0VarA = b0VarD.a(V.e(AbstractC0240f.q(1, new androidx.compose.ui.unit.j(R5.a(1, 1))), androidx.compose.ui.b.i, C0229c.l));
            int i3 = i2 << 3;
            h(I0.c(t, "AnimatedVisibility", c0814p, (i2 & 14) | 48), C0229c.f, qVar, a0Var, b0VarA, dVar, c0814p, (i3 & 7168) | (i3 & 896) | 48 | 221184);
            b0Var2 = b0VarA;
            str2 = "AnimatedVisibility";
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0284k(t, qVar, a0Var, b0Var2, str2, dVar, i);
        }
    }

    public static final void e(H0 h0, boolean z, androidx.compose.ui.n nVar, a0 a0Var, b0 b0Var, String str, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        C0814p c0814p;
        String str2;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1741346906);
        if ((i & 48) == 0) {
            i2 = (c0814p2.g(z) ? 32 : 16) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 384;
        if ((i & 3072) == 0) {
            i3 |= c0814p2.f(a0Var) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p2.f(b0Var) ? 16384 : 8192;
        }
        int i4 = i3 | 196608;
        if ((1572864 & i) == 0) {
            i4 |= c0814p2.h(dVar) ? 1048576 : 524288;
        }
        if ((599185 & i4) == 599184 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
            str2 = str;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            int i5 = i4 >> 3;
            h(I0.d(Boolean.valueOf(z), "AnimatedVisibility", c0814p2, (i5 & 14) | ((i4 >> 12) & ContentType.LONG_FORM_ON_DEMAND), 0), C0229c.d, nVar3, a0Var, b0Var, dVar, c0814p2, (i4 & 57344) | (i4 & 896) | 48 | (i4 & 7168) | (i5 & 458752));
            nVar2 = nVar3;
            c0814p = c0814p2;
            str2 = "AnimatedVisibility";
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new B(h0, z, nVar2, a0Var, b0Var, str2, dVar, i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x003b  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0040  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0093  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00c5  */
    /* JADX WARN: Removed duplicated region for block: B:45:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void f(boolean r16, androidx.compose.ui.n r17, androidx.compose.animation.a0 r18, androidx.compose.animation.b0 r19, java.lang.String r20, kotlin.jvm.functions.c r21, androidx.compose.runtime.InterfaceC0806l r22, int r23, int r24) {
        /*
            Method dump skipped, instructions count: 210
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.E.f(boolean, androidx.compose.ui.n, androidx.compose.animation.a0, androidx.compose.animation.b0, java.lang.String, kotlin.jvm.functions.c, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x003f  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:56:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void g(boolean r16, androidx.compose.ui.q r17, androidx.compose.animation.a0 r18, androidx.compose.animation.b0 r19, java.lang.String r20, androidx.compose.runtime.internal.d r21, androidx.compose.runtime.InterfaceC0806l r22, int r23, int r24) {
        /*
            Method dump skipped, instructions count: 210
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.E.g(boolean, androidx.compose.ui.q, androidx.compose.animation.a0, androidx.compose.animation.b0, java.lang.String, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int, int):void");
    }

    public static final void h(E0 e0, Function1 function1, androidx.compose.ui.q qVar, a0 a0Var, b0 b0Var, kotlin.jvm.functions.c cVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        a0 a0Var2;
        b0 b0Var2;
        kotlin.jvm.functions.c cVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(429978603);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(e0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            a0Var2 = a0Var;
            i2 |= c0814p.f(a0Var2) ? 2048 : 1024;
        } else {
            a0Var2 = a0Var;
        }
        if ((i & 24576) == 0) {
            b0Var2 = b0Var;
            i2 |= c0814p.f(b0Var2) ? 16384 : 8192;
        } else {
            b0Var2 = b0Var;
        }
        if ((i & 196608) == 0) {
            cVar2 = cVar;
            i2 |= c0814p.h(cVar2) ? 131072 : 65536;
        } else {
            cVar2 = cVar;
        }
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i3 = i2 & ContentType.LONG_FORM_ON_DEMAND;
            int i4 = i2 & 14;
            boolean z = (i3 == 32) | (i4 == 4);
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new D(function1, e0);
                c0814p.i0(objI);
            }
            c(e0, function1, AbstractC0897s.j(qVar, (kotlin.jvm.functions.c) objI), a0Var2, b0Var2, C0286m.c, cVar2, c0814p, 196608 | i4 | i3 | (i2 & 7168) | (57344 & i2) | ((i2 << 6) & 29360128));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0285l(e0, function1, qVar, a0Var, b0Var, cVar, i);
        }
    }

    public static final void i(E0 e0, androidx.compose.ui.q qVar, K0 k0, C0229c c0229c, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.runtime.internal.d dVar2;
        boolean z;
        C0229c c0229c2;
        E0 e02 = e0;
        int i2 = 0;
        boolean z2 = true;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(679005231);
        int i3 = (i & 6) == 0 ? (c0814p.f(e02) ? 4 : 2) | i : i;
        if ((i & 48) == 0) {
            i3 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i3 |= c0814p.h(k0) ? 256 : 128;
        }
        int i4 = i3 | 3072;
        if ((i & 24576) == 0) {
            dVar2 = dVar;
            i4 |= c0814p.h(dVar2) ? 16384 : 8192;
        } else {
            dVar2 = dVar;
        }
        if ((i4 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            c0229c2 = c0229c;
        } else {
            C0229c c0229c3 = C0229c.h;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            J0 j0 = e02.a;
            Object obj = objI;
            if (objI == v) {
                androidx.compose.runtime.snapshots.q qVar2 = new androidx.compose.runtime.snapshots.q();
                qVar2.add(j0.t());
                c0814p.i0(qVar2);
                obj = qVar2;
            }
            androidx.compose.runtime.snapshots.q qVar3 = (androidx.compose.runtime.snapshots.q) obj;
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                long[] jArr = androidx.collection.S.a;
                objI2 = new androidx.collection.I();
                c0814p.i0(objI2);
            }
            androidx.collection.I i5 = (androidx.collection.I) objI2;
            Object objT = j0.t();
            L0 l0 = (L0) e02.d;
            if (Intrinsics.b(objT, l0.getValue())) {
                c0814p.X(860660313);
                if (qVar3.size() == 1 && Intrinsics.b(qVar3.get(0), l0.getValue())) {
                    c0814p.X(860984945);
                    c0814p.p(false);
                } else {
                    c0814p.X(860794667);
                    boolean z3 = (i4 & 14) == 4;
                    Object objI3 = c0814p.I();
                    if (z3 || objI3 == v) {
                        objI3 = new L(e02, i2);
                        c0814p.i0(objI3);
                    }
                    kotlin.collections.G.y(qVar3, (Function1) objI3);
                    i5.a();
                    c0814p.p(false);
                }
                c0814p.p(false);
            } else {
                c0814p.X(860990897);
                c0814p.p(false);
            }
            if (i5.b(l0.getValue())) {
                z = true;
                c0814p.X(861812273);
                c0814p.p(false);
            } else {
                c0814p.X(861052122);
                ListIterator listIterator = qVar3.listIterator();
                int i6 = 0;
                while (true) {
                    androidx.compose.runtime.snapshots.w wVar = (androidx.compose.runtime.snapshots.w) listIterator;
                    z = z2;
                    if (!wVar.hasNext()) {
                        i6 = -1;
                        break;
                    } else {
                        if (Intrinsics.b(wVar.next(), l0.getValue())) {
                            break;
                        }
                        i6++;
                        z2 = z;
                    }
                }
                if (i6 == -1) {
                    qVar3.add(l0.getValue());
                } else {
                    qVar3.set(i6, l0.getValue());
                }
                i5.a();
                int size = qVar3.size();
                int i7 = 0;
                while (i7 < size) {
                    Object obj2 = qVar3.get(i7);
                    i5.j(obj2, androidx.compose.runtime.internal.e.e(-1426421288, new N(e02, k0, obj2, dVar2, 0), c0814p));
                    i7++;
                    e02 = e0;
                    dVar2 = dVar;
                }
                c0814p.p(false);
            }
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i8 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(-187482432);
            int size2 = qVar3.size();
            for (int i9 = 0; i9 < size2; i9++) {
                Object obj3 = qVar3.get(i9);
                c0814p.U(-1081873445, obj3);
                Function2 function2 = (Function2) i5.f(obj3);
                if (function2 == null) {
                    c0814p.X(821713034);
                } else {
                    c0814p.X(-1081871785);
                    function2.invoke(c0814p, 0);
                }
                c0814p.p(false);
                c0814p.p(false);
            }
            c0814p.p(false);
            c0814p.p(z);
            c0229c2 = c0229c3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new K(e0, qVar, k0, c0229c2, dVar, i, 1);
        }
    }

    public static final void j(Boolean bool, androidx.compose.ui.n nVar, K0 k0, String str, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        String str2;
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-310686752);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(bool) : c0814p.h(bool) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i & 384) == 0) {
            i3 |= c0814p.h(k0) ? 256 : 128;
        }
        int i4 = i3 | 3072;
        if ((i & 24576) == 0) {
            i4 |= c0814p.h(dVar) ? 16384 : 8192;
        }
        if ((i4 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
            str2 = str;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            i(I0.d(bool, "Crossfade", c0814p, (i4 & 14) | ((i4 >> 6) & ContentType.LONG_FORM_ON_DEMAND), 0), nVar3, k0, null, dVar, c0814p, i4 & 58352);
            str2 = "Crossfade";
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new K(bool, nVar2, k0, str2, dVar, i, 0);
        }
    }

    public static final O k(E0 e0, Function1 function1, Object obj, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.U(-902048200, e0);
        boolean zH = e0.h();
        O o = O.a;
        O o2 = O.c;
        O o3 = O.b;
        J0 j0 = e0.a;
        if (zH) {
            c0814p.X(2101296683);
            c0814p.p(false);
            if (((Boolean) function1.invoke(obj)).booleanValue()) {
                o = o3;
            } else if (((Boolean) function1.invoke(j0.t())).booleanValue()) {
                o = o2;
            }
        } else {
            c0814p.X(2101530516);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = C0776c.z(Boolean.FALSE);
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            if (((Boolean) function1.invoke(j0.t())).booleanValue()) {
                interfaceC0773a0.setValue(Boolean.TRUE);
            }
            if (((Boolean) function1.invoke(obj)).booleanValue()) {
                o = o3;
            } else if (((Boolean) interfaceC0773a0.getValue()).booleanValue()) {
                o = o2;
            }
            c0814p.p(false);
        }
        c0814p.p(false);
        return o;
    }

    public static final J l(a0 a0Var, b0 b0Var) {
        return new J(a0Var, b0Var, DefinitionKt.NO_Float_VALUE, new n0(C0286m.b));
    }
}
