package androidx.compose.material3;

import androidx.compose.animation.C0229c;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0274x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.y1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0762y1 {
    static {
        int i = 1;
        C0274x c0274x = androidx.compose.material3.tokens.p.c;
        androidx.compose.animation.b0 b0VarD = androidx.compose.animation.V.d(AbstractC0240f.r(100, 0, c0274x, 2), 2);
        C0274x c0274x2 = androidx.compose.material3.tokens.p.a;
        androidx.compose.animation.core.D dR = AbstractC0240f.r(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR, 0, c0274x2, 2);
        androidx.compose.ui.g gVar = androidx.compose.ui.b.m;
        if ((12 & 1) != 0) {
            Object obj = androidx.compose.animation.core.V0.a;
            dR = AbstractC0240f.q(1, new androidx.compose.ui.unit.j(R5.a(1, 1)));
        }
        int i2 = 12 & 2;
        androidx.compose.ui.g gVar2 = androidx.compose.ui.b.o;
        androidx.compose.ui.g gVar3 = i2 != 0 ? gVar2 : gVar;
        b0VarD.a(androidx.compose.animation.V.e(dR, Intrinsics.b(gVar3, gVar) ? androidx.compose.ui.b.d : Intrinsics.b(gVar3, gVar2) ? androidx.compose.ui.b.f : androidx.compose.ui.b.e, new C0229c(i, 16)));
        androidx.compose.animation.a0 a0VarC = androidx.compose.animation.V.c(new androidx.compose.animation.core.K0(200, 100, c0274x), 2);
        androidx.compose.animation.core.D dR2 = AbstractC0240f.r(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR, 0, c0274x2, 2);
        androidx.compose.ui.g gVar4 = androidx.compose.ui.b.m;
        if ((12 & 1) != 0) {
            Object obj2 = androidx.compose.animation.core.V0.a;
            dR2 = AbstractC0240f.q(1, new androidx.compose.ui.unit.j(R5.a(1, 1)));
        }
        int i3 = 2 & 12;
        androidx.compose.ui.g gVar5 = androidx.compose.ui.b.o;
        androidx.compose.ui.g gVar6 = i3 != 0 ? gVar5 : gVar4;
        a0VarC.a(androidx.compose.animation.V.a(dR2, Intrinsics.b(gVar6, gVar4) ? androidx.compose.ui.b.d : Intrinsics.b(gVar6, gVar5) ? androidx.compose.ui.b.f : androidx.compose.ui.b.e, new C0229c(i, 14)));
    }

    public static final void a(Function0 function0, androidx.compose.ui.q qVar, androidx.compose.ui.graphics.V v, long j, long j2, C0717s1 c0717s1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.graphics.V v2;
        int i3;
        long j3;
        C0717s1 c0717s12;
        int i4;
        C0814p c0814p;
        C0717s1 c0717s13;
        long j4;
        androidx.compose.runtime.internal.d dVar = com.quizlet.upgrade.confirmation.composables.b.a;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-731723913);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            v2 = v;
            i2 |= c0814p2.f(v2) ? 256 : 128;
        } else {
            v2 = v;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.e(j) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= 65536;
        }
        int i5 = i2 | 1572864;
        if ((12582912 & i) == 0) {
            i5 |= c0814p2.h(dVar) ? 8388608 : 4194304;
        }
        if ((4793491 & i5) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            j4 = j2;
            c0717s13 = c0717s1;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                long jB = AbstractC0590b0.b(j, c0814p2);
                int i6 = AbstractC0694o1.a;
                i3 = i5 & (-516097);
                j3 = jB;
                c0717s12 = new C0717s1(androidx.compose.material3.tokens.j.a, androidx.compose.material3.tokens.j.f, androidx.compose.material3.tokens.j.d, androidx.compose.material3.tokens.j.e);
            } else {
                c0814p2.Q();
                j3 = j2;
                i3 = i5 & (-516097);
                c0717s12 = c0717s1;
            }
            c0814p2.q();
            c0814p2.X(519755085);
            Object obj = C0804k.a;
            Object objI = c0814p2.I();
            if (objI == obj) {
                objI = androidx.compose.animation.d0.i(c0814p2);
            }
            androidx.compose.foundation.interaction.l lVar = (androidx.compose.foundation.interaction.l) objI;
            c0814p2.p(false);
            androidx.compose.ui.q qVarA = androidx.compose.ui.semantics.m.a(qVar, false, C0736u.m);
            float f = c0717s12.a;
            boolean zF = c0814p2.f(lVar);
            Object objI2 = c0814p2.I();
            if (zF || objI2 == obj) {
                i4 = i3;
                objI2 = new C0744v1(c0717s12.a, c0717s12.b, c0717s12.d, c0717s12.c);
                c0814p2.i0(objI2);
            } else {
                i4 = i3;
            }
            C0744v1 c0744v1 = (C0744v1) objI2;
            boolean zH = c0814p2.h(c0744v1) | c0814p2.f(c0717s12);
            Object objI3 = c0814p2.I();
            if (zH || objI3 == obj) {
                objI3 = new C0700p1(c0744v1, c0717s12, null);
                c0814p2.i0(objI3);
            }
            C0776c.f(c0814p2, c0717s12, (Function2) objI3);
            boolean zF2 = c0814p2.f(lVar) | c0814p2.h(c0744v1);
            Object objI4 = c0814p2.I();
            if (zF2 || objI4 == obj) {
                objI4 = new C0711r1(lVar, c0744v1, null);
                c0814p2.i0(objI4);
            }
            C0776c.f(c0814p2, lVar, (Function2) objI4);
            int i7 = i4 << 3;
            c0814p = c0814p2;
            AbstractC0594b4.c(function0, qVarA, false, v2, j, j3, f, ((androidx.compose.ui.unit.e) ((androidx.compose.runtime.L0) c0744v1.e.c.b).getValue()).a, null, lVar, androidx.compose.runtime.internal.e.e(1249316354, new C0750w1(j3), c0814p2), c0814p, (i4 & 14) | (i7 & 7168) | (i7 & 57344), 260);
            c0717s13 = c0717s12;
            j4 = j3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0756x1(function0, qVar, v, j, j4, c0717s13, i);
        }
    }
}
