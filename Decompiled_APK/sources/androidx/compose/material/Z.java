package androidx.compose.material;

import android.content.Context;
import androidx.compose.animation.C0281h;
import androidx.compose.animation.core.AbstractC0248j;
import androidx.compose.animation.core.C0242g;
import androidx.compose.animation.core.C0253l0;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.layout.K0;
import androidx.compose.foundation.text.selection.n0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.W0;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3244r0;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class Z {
    public static final float a = 56;
    public static final float b = 125;
    public static final float c = 640;

    public static final void a(androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, e0 e0Var, boolean z, androidx.compose.foundation.shape.d dVar2, float f, long j, long j2, long j3, androidx.compose.runtime.internal.d dVar3, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.runtime.internal.d dVar4;
        androidx.compose.ui.q qVarA;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-92970288);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(dVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(e0Var) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.g(z) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(dVar2) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.c(f) ? 131072 : 65536;
        }
        if ((i & 1572864) == 0) {
            i2 |= c0814p.e(j) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.e(j2) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i2 |= c0814p.e(j3) ? 67108864 : 33554432;
        }
        if ((805306368 & i) == 0) {
            i2 |= c0814p.h(dVar3) ? 536870912 : 268435456;
        }
        if (c0814p.N(i2 & 1, (306783379 & i2) != 306783378)) {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (objI == obj) {
                objI = C0776c.n(kotlin.coroutines.n.a, c0814p);
                c0814p.i0(objI);
            }
            kotlinx.coroutines.C c2 = (kotlinx.coroutines.C) objI;
            EnumC0320d0 enumC0320d0 = EnumC0320d0.a;
            androidx.compose.ui.i iVar = androidx.compose.ui.b.a;
            int i3 = i2;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            Function0 function0 = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(function0);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, kE, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            C0418x c0418x = C0418x.a;
            androidx.compose.ui.q qVarA2 = androidx.compose.ui.n.b;
            FillElement fillElement = K0.c;
            androidx.compose.ui.layout.K kE2 = AbstractC0409s.e(iVar, false);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, fillElement);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(function0);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            dVar3.invoke(c0814p, Integer.valueOf((i3 >> 27) & 14));
            boolean zH = c0814p.h(e0Var) | c0814p.h(c2);
            Object objI2 = c0814p.I();
            if (zH || objI2 == obj) {
                objI2 = new M(e0Var, c2, 0);
                c0814p.i0(objI2);
            }
            Function0 function02 = (Function0) objI2;
            Object value = e0Var.a.g.getValue();
            f0 f0Var = f0.a;
            b(j3, function02, value != f0Var, c0814p, (i3 >> 24) & 14);
            c0814p.p(true);
            androidx.compose.ui.q qVarC3 = K0.c(K0.q(c0418x.a(qVarA2, androidx.compose.ui.b.b), DefinitionKt.NO_Float_VALUE, c, 1), 1.0f);
            kotlin.coroutines.h hVar = null;
            C0575s c0575s = e0Var.a;
            if (z) {
                c0814p.X(-892908339);
                boolean zF = c0814p.f(c0575s);
                Object objI3 = c0814p.I();
                if (zF || objI3 == obj) {
                    objI3 = new K(c0575s);
                    c0814p.i0(objI3);
                }
                qVarA = androidx.compose.ui.input.nestedscroll.f.a(qVarA2, (androidx.compose.ui.input.nestedscroll.a) objI3, null);
                c0814p.p(false);
            } else {
                c0814p.X(-167335778);
                c0814p.p(false);
                qVarA = qVarA2;
            }
            androidx.compose.ui.q qVarA3 = androidx.compose.foundation.gestures.U.a(qVarC3.g(qVarA).g(new DraggableAnchorsElement(c0575s, new C0281h(e0Var, 14))), c0575s.e, enumC0320d0, z && ((L0) c0575s.f).getValue() != f0Var, ((L0) c0575s.k).getValue() != null, new C0559b(c0575s, hVar, 0), 32);
            if (z) {
                c0814p.X(-891907876);
                boolean zH2 = c0814p.h(e0Var) | c0814p.h(c2);
                Object objI4 = c0814p.I();
                if (zH2 || objI4 == obj) {
                    objI4 = new n0(1, e0Var, c2);
                    c0814p.i0(objI4);
                }
                qVarA2 = androidx.compose.ui.semantics.m.a(qVarA2, false, (Function1) objI4);
                c0814p.p(false);
            } else {
                c0814p.X(-167257346);
                c0814p.p(false);
            }
            dVar4 = dVar;
            int i6 = i3 >> 12;
            AbstractC3244r0.c(qVarA3.g(qVarA2), dVar2, j, j2, f, androidx.compose.runtime.internal.e.e(17396558, new androidx.compose.foundation.layout.W(dVar4, 3, (byte) 0), c0814p), c0814p, ((i3 >> 9) & ContentType.LONG_FORM_ON_DEMAND) | 1572864 | (i6 & 896) | (i6 & 7168) | (i3 & 458752));
            c0814p.p(true);
        } else {
            dVar4 = dVar;
            c0814p.Q();
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Q(dVar4, qVar, e0Var, z, dVar2, f, j, j2, j3, dVar3, i);
        }
    }

    public static final void b(long j, Function0 function0, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-526532668);
        if ((i & 6) == 0) {
            i2 = (c0814p.e(j) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z) ? 256 : 128;
        }
        if (!c0814p.N(i2 & 1, (i2 & 147) != 146)) {
            c0814p.Q();
        } else if (j != 16) {
            c0814p.X(477792612);
            boolean z2 = true;
            W0 w0B = AbstractC0248j.b(z ? 1.0f : DefinitionKt.NO_Float_VALUE, new androidx.compose.animation.core.K0(0, (androidx.compose.animation.core.B) null, 7), null, null, c0814p, 48, 28);
            c0814p.j(AndroidCompositionLocals_androidKt.a);
            String string = ((Context) c0814p.j(AndroidCompositionLocals_androidKt.b)).getResources().getString(R.string.close_sheet);
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarA = androidx.compose.ui.n.b;
            if (z) {
                c0814p.X(478010511);
                int i3 = i2 & ContentType.LONG_FORM_ON_DEMAND;
                boolean z3 = i3 == 32;
                Object objI = c0814p.I();
                if (z3 || objI == v) {
                    objI = new U(function0, null);
                    c0814p.i0(objI);
                }
                androidx.compose.ui.q qVarA2 = androidx.compose.ui.input.pointer.v.a(qVarA, function0, (Function2) objI);
                boolean zF = (i3 == 32) | c0814p.f(string);
                Object objI2 = c0814p.I();
                if (zF || objI2 == v) {
                    objI2 = new W(string, function0, 0);
                    c0814p.i0(objI2);
                }
                z2 = true;
                qVarA = androidx.compose.ui.semantics.m.a(qVarA2, true, (Function1) objI2);
                c0814p.p(false);
            } else {
                c0814p.X(478374234);
                c0814p.p(false);
            }
            androidx.compose.ui.q qVarG = K0.c.g(qVarA);
            if ((i2 & 14) != 4) {
                z2 = false;
            }
            boolean zF2 = c0814p.f(w0B) | z2;
            Object objI3 = c0814p.I();
            if (zF2 || objI3 == v) {
                objI3 = new S(j, w0B, 0);
                c0814p.i0(objI3);
            }
            AbstractC0460p.b(qVarG, (Function1) objI3, c0814p, 0);
            c0814p.p(false);
        } else {
            c0814p.X(478559490);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new T(j, function0, z, i, 0);
        }
    }

    public static final e0 c(C0253l0 c0253l0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        boolean z = false;
        Object obj = f0.a;
        int i3 = 2;
        androidx.compose.animation.core.D d = c0253l0;
        if ((i2 & 2) != 0) {
            d = H.b;
        }
        Object obj2 = Y.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
        c0814p.U(976451635, obj);
        Object[] objArr = {obj, d, false, obj2, bVar};
        a0 a0Var = a0.a;
        n0 n0Var = new n0(i3, bVar, d);
        com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.runtime.saveable.m.a;
        com.quizlet.data.repository.explanations.myexplanations.a aVar2 = new com.quizlet.data.repository.explanations.myexplanations.a(a0Var, z, n0Var, 3);
        boolean z2 = true;
        boolean zF = ((((i & 896) ^ 384) > 256 && c0814p.f(obj2)) || (i & 384) == 256) | ((((i & 14) ^ 6) > 4 && c0814p.f(obj)) || (i & 6) == 4) | c0814p.f(bVar) | c0814p.h(d);
        if ((((i & 7168) ^ 3072) <= 2048 || !c0814p.g(false)) && (i & 3072) != 2048) {
            z2 = false;
        }
        boolean z3 = zF | z2;
        Object objI = c0814p.I();
        if (z3 || objI == C0804k.a) {
            objI = new C0242g(bVar, d);
            c0814p.i0(objI);
        }
        e0 e0Var = (e0) L4.d(objArr, aVar2, (Function0) objI, c0814p, 0, 4);
        c0814p.p(false);
        return e0Var;
    }
}
