package androidx.compose.ui.layout;

import androidx.compose.foundation.gestures.C0346q0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0798h;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0810n;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.layout.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0897s {
    public static final P a = new P(7);

    public static final void a(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, K k, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1949933075);
        int i2 = 2;
        if ((((c0814p.f(qVar) ? 4 : 2) | i | (c0814p.f(k) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i3 = c0814p.P;
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            C0913i c0913i = C0913i.d;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            InterfaceC0915k.D0.getClass();
            C0776c.E(c0814p, k, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            if (c0814p.O) {
                c0814p.b(Unit.a, new C0798h(i2, 2));
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            androidx.compose.animation.d0.w(6, dVar, c0814p, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0346q0(i, 6, qVar, dVar, k);
        }
    }

    public static final long b(float f, float f2) {
        long jFloatToRawIntBits = (Float.floatToRawIntBits(f2) & 4294967295L) | (Float.floatToRawIntBits(f) << 32);
        int i = a0.b;
        return jFloatToRawIntBits;
    }

    public static final void c(androidx.compose.ui.q qVar, Function2 function2, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1298353104);
        int i4 = i2 & 1;
        if (i4 != 0) {
            i3 = i | 6;
        } else if ((i & 6) == 0) {
            i3 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.h(function2) ? 32 : 16;
        }
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i4 != 0) {
                qVar = androidx.compose.ui.n.b;
            }
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new e0(P.b);
                c0814p.i0(objI);
            }
            d((e0) objI, qVar, function2, c0814p, (i3 << 3) & 1008);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new b0(qVar, function2, i, i2);
        }
    }

    public static final void d(e0 e0Var, androidx.compose.ui.q qVar, Function2 function2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-511989831);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(e0Var) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function2) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i3 = c0814p.P;
            C0810n c0810nC = C0776c.C(c0814p);
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            C0913i c0913i = C0913i.d;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, e0Var, e0Var.c);
            C0776c.E(c0814p, c0810nC, e0Var.d);
            C0776c.E(c0814p, function2, e0Var.e);
            InterfaceC0915k.D0.getClass();
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            c0814p.p(true);
            if (c0814p.x()) {
                c0814p.X(-26502501);
                c0814p.p(false);
            } else {
                c0814p.X(-26580342);
                boolean zH = c0814p.h(e0Var);
                Object objI = c0814p.I();
                if (zH || objI == C0804k.a) {
                    objI = new androidx.compose.ui.input.nestedscroll.b(e0Var, 2);
                    c0814p.i0(objI);
                }
                C0776c.i((Function0) objI, c0814p);
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.a(i, 7, e0Var, qVar, function2);
        }
    }

    public static final androidx.compose.ui.geometry.c e(r rVar) {
        r rVarH = rVar.H();
        return rVarH != null ? rVarH.o(rVar, true) : new androidx.compose.ui.geometry.c(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, (int) (rVar.t() >> 32), (int) (rVar.t() & 4294967295L));
    }

    public static final androidx.compose.ui.geometry.c f(r rVar) {
        r rVarG = g(rVar);
        float fT = (int) (rVarG.t() >> 32);
        float fT2 = (int) (rVarG.t() & 4294967295L);
        androidx.compose.ui.geometry.c cVarO = g(rVar).o(rVar, true);
        float f = cVarO.a;
        float f2 = DefinitionKt.NO_Float_VALUE;
        if (f < DefinitionKt.NO_Float_VALUE) {
            f = 0.0f;
        }
        if (f > fT) {
            f = fT;
        }
        float f3 = cVarO.b;
        if (f3 < DefinitionKt.NO_Float_VALUE) {
            f3 = 0.0f;
        }
        if (f3 > fT2) {
            f3 = fT2;
        }
        float f4 = cVarO.c;
        if (f4 < DefinitionKt.NO_Float_VALUE) {
            f4 = 0.0f;
        }
        if (f4 <= fT) {
            fT = f4;
        }
        float f5 = cVarO.d;
        if (f5 >= DefinitionKt.NO_Float_VALUE) {
            f2 = f5;
        }
        if (f2 <= fT2) {
            fT2 = f2;
        }
        if (f == fT || f3 == fT2) {
            return androidx.compose.ui.geometry.c.e;
        }
        long jD = rVarG.d(Q4.c(f, f3));
        long jD2 = rVarG.d(Q4.c(fT, f3));
        long jD3 = rVarG.d(Q4.c(fT, fT2));
        long jD4 = rVarG.d(Q4.c(f, fT2));
        float fD = androidx.compose.ui.geometry.b.d(jD);
        float fD2 = androidx.compose.ui.geometry.b.d(jD2);
        float fD3 = androidx.compose.ui.geometry.b.d(jD4);
        float fD4 = androidx.compose.ui.geometry.b.d(jD3);
        float fMin = Math.min(fD, Math.min(fD2, Math.min(fD3, fD4)));
        float fMax = Math.max(fD, Math.max(fD2, Math.max(fD3, fD4)));
        float fE = androidx.compose.ui.geometry.b.e(jD);
        float fE2 = androidx.compose.ui.geometry.b.e(jD2);
        float fE3 = androidx.compose.ui.geometry.b.e(jD4);
        float fE4 = androidx.compose.ui.geometry.b.e(jD3);
        return new androidx.compose.ui.geometry.c(fMin, Math.min(fE, Math.min(fE2, Math.min(fE3, fE4))), fMax, Math.max(fE, Math.max(fE2, Math.max(fE3, fE4))));
    }

    public static final r g(r rVar) {
        r rVar2;
        r rVarH = rVar.H();
        while (true) {
            r rVar3 = rVarH;
            rVar2 = rVar;
            rVar = rVar3;
            if (rVar == null) {
                break;
            }
            rVarH = rVar.H();
        }
        androidx.compose.ui.node.a0 a0Var = rVar2 instanceof androidx.compose.ui.node.a0 ? (androidx.compose.ui.node.a0) rVar2 : null;
        if (a0Var == null) {
            return rVar2;
        }
        androidx.compose.ui.node.a0 a0Var2 = a0Var.n;
        while (true) {
            androidx.compose.ui.node.a0 a0Var3 = a0Var2;
            androidx.compose.ui.node.a0 a0Var4 = a0Var;
            a0Var = a0Var3;
            if (a0Var == null) {
                return a0Var4;
            }
            a0Var2 = a0Var.n;
        }
    }

    public static final Object h(J j) {
        Object objG = j.G();
        InterfaceC0899u interfaceC0899u = objG instanceof InterfaceC0899u ? (InterfaceC0899u) objG : null;
        if (interfaceC0899u != null) {
            return interfaceC0899u.t();
        }
        return null;
    }

    public static final androidx.compose.ui.node.P i(androidx.compose.ui.node.P p) {
        androidx.compose.ui.node.E e = p.l.l;
        while (true) {
            androidx.compose.ui.node.E eS = e.s();
            androidx.compose.ui.node.E e2 = null;
            if ((eS != null ? eS.c : null) == null) {
                androidx.compose.ui.node.P pU0 = ((androidx.compose.ui.node.a0) e.w.d).U0();
                Intrinsics.d(pU0);
                return pU0;
            }
            androidx.compose.ui.node.E eS2 = e.s();
            if (eS2 != null) {
                e2 = eS2.c;
            }
            Intrinsics.d(e2);
            androidx.compose.ui.node.E eS3 = e.s();
            Intrinsics.d(eS3);
            e = eS3.c;
            Intrinsics.d(e);
        }
    }

    public static final androidx.compose.ui.q j(androidx.compose.ui.q qVar, kotlin.jvm.functions.c cVar) {
        return qVar.g(new LayoutElement(cVar));
    }

    public static final androidx.compose.ui.q k(androidx.compose.ui.q qVar, String str) {
        return qVar.g(new LayoutIdElement(str));
    }

    public static final androidx.compose.ui.q l(androidx.compose.ui.q qVar, Function1 function1) {
        return qVar.g(new OnGloballyPositionedElement(function1));
    }

    public static final androidx.compose.ui.q m(androidx.compose.ui.q qVar, Function1 function1) {
        return qVar.g(new OnSizeChangedModifier(function1));
    }

    public static final long n(long j, long j2) {
        return T4.a(a0.a(j2) * androidx.compose.ui.geometry.e.d(j), a0.b(j2) * androidx.compose.ui.geometry.e.b(j));
    }
}
