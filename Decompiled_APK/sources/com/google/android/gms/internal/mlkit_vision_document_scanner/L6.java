package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.quizlet.diagrams.ui.DiagramJSBridge;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class L6 {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Removed duplicated region for block: B:100:0x0128  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x012e  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x0136  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x013b  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x013e  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0150  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x02c1  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x02d2  */
    /* JADX WARN: Removed duplicated region for block: B:150:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0059  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x005f  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0081  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0096  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x009e  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00a2  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00b9  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00bd  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0121  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0123  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final com.quizlet.studiablemodels.diagrams.DiagramData r21, androidx.compose.ui.q r22, com.quizlet.diagrams.b[] r23, boolean r24, com.quizlet.diagrams.ui.i r25, com.quizlet.diagrams.ui.DiagramJSBridge r26, kotlin.jvm.functions.Function0 r27, kotlin.jvm.functions.Function0 r28, androidx.compose.runtime.InterfaceC0806l r29, final int r30, final int r31) {
        /*
            Method dump skipped, instructions count: 730
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.L6.a(com.quizlet.studiablemodels.diagrams.DiagramData, androidx.compose.ui.q, com.quizlet.diagrams.b[], boolean, com.quizlet.diagrams.ui.i, com.quizlet.diagrams.ui.DiagramJSBridge, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(String str, DiagramJSBridge diagramJSBridge, androidx.compose.ui.q qVar, boolean z, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(24378511);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(str) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(diagramJSBridge) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.g(z) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function0) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function02) ? 131072 : 65536;
        }
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.d();
            float f = com.quizlet.ui.resources.designsystem.generated.f.g;
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.draw.g.c(qVarC, androidx.compose.foundation.shape.e.a(f));
            float f2 = com.quizlet.themes.m.i;
            long jK = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.k();
            mVar.d();
            androidx.compose.ui.q qVarG = AbstractC0460p.g(qVarC2, f2, jK, androidx.compose.foundation.shape.e.a(f));
            androidx.compose.ui.i iVar = androidx.compose.ui.b.a;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            int i4 = i2;
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, kE, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC3, c0912h4);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarG2 = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(nVar, 1.0f), "diagram");
            c0814p.X(-2079489853);
            boolean zH = ((i4 & 458752) == 131072) | c0814p.h(diagramJSBridge);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                objI = new androidx.lifecycle.u0(12, diagramJSBridge, function02);
                c0814p.i0(objI);
            }
            Function1 function1 = (Function1) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-2079460955, c0814p, false);
            if (objG == v) {
                objG = new com.quizlet.assembly.compose.buttons.Z(4);
                c0814p.i0(objG);
            }
            Function1 function12 = (Function1) objG;
            c0814p.p(false);
            c0814p.X(-2079464236);
            boolean z3 = (i4 & 14) == 4;
            Object objI2 = c0814p.I();
            if (z3 || objI2 == v) {
                objI2 = new androidx.navigation.internal.h(str, 13);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            androidx.compose.ui.viewinterop.k.b(function1, qVarG2, function12, null, (Function1) objI2, c0814p, 432, 8);
            c0814p.X(-2079459888);
            if (z) {
                androidx.compose.ui.q qVarG3 = androidx.compose.ui.draw.g.a(AbstractC0460p.f(nVar, C0861v.f, androidx.compose.ui.graphics.F.a), DefinitionKt.NO_Float_VALUE).g(androidx.compose.foundation.layout.K0.c);
                c0814p.X(-2079452841);
                boolean z4 = (i4 & 57344) == 16384;
                Object objI3 = c0814p.I();
                if (z4 || objI3 == v) {
                    objI3 = new com.braze.support.u(8, function0);
                    c0814p.i0(objI3);
                }
                c0814p.p(false);
                androidx.compose.ui.q qVarG4 = androidx.compose.ui.platform.N.G(AbstractC0460p.l(qVarG3, false, null, (Function0) objI3, 7), "transparentOverlay");
                androidx.compose.ui.layout.K kE2 = AbstractC0409s.e(iVar, false);
                int i5 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
                androidx.compose.ui.q qVarC4 = androidx.compose.ui.a.c(c0814p, qVarG4);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, kE2, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                    android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
                }
                C0776c.E(c0814p, qVarC4, c0912h4);
                z2 = true;
                c0814p.p(true);
            } else {
                z2 = true;
            }
            c0814p.p(false);
            c0814p.p(z2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.diagrams.ui.f(str, diagramJSBridge, qVar, z, function0, function02, i);
        }
    }
}
