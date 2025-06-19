package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.vector.C0866e;
import androidx.compose.ui.graphics.vector.C0867f;
import androidx.compose.ui.graphics.vector.C0868g;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import com.quizlet.features.achievements.ui.composables.C4218e;
import com.quizlet.search.data.term.TermUiModel;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Set;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class D0 {
    public static C0867f a;

    public static final void a(androidx.compose.ui.n nVar, String str, boolean z, Function1 function1, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(684994706);
        int i2 = i | 6;
        if ((i & 48) == 0) {
            i2 |= c0814p.f(str) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function1) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function0) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p.Q();
                nVar2 = nVar;
            }
            c0814p.q();
            androidx.compose.animation.E.g(z, null, androidx.compose.animation.V.c(null, 3), androidx.compose.animation.V.d(null, 3), null, androidx.compose.runtime.internal.e.e(-439191702, new com.quizlet.features.folders.addtofolder.composables.r((androidx.compose.ui.focus.h) c0814p.j(AbstractC0955m0.g), function1, 0), c0814p), c0814p, ((i2 >> 6) & 14) | 200064, 18);
            androidx.compose.animation.E.g(!z, null, androidx.compose.animation.V.c(null, 3).a(androidx.compose.animation.V.b(null, 13)), androidx.compose.animation.V.d(null, 3).a(androidx.compose.animation.V.f(null, 13)), null, androidx.compose.runtime.internal.e.e(625748065, new com.quizlet.assembly.compose.menu.g(nVar2, str, function0, function1), c0814p), c0814p, 200064, 18);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.addtofolder.composables.q(nVar2, str, z, function1, function0, i);
        }
    }

    public static final void b(TermUiModel termUiModel, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(113362610);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(termUiModel) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, nVar);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            String str = termUiModel.a;
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            i(0, 0, c0814p, new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true), str);
            f(termUiModel.c, c0814p, 0);
            c0814p.p(true);
            c(termUiModel.b, null, c0814p, 0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.search.composables.L(termUiModel, i, 0);
        }
    }

    public static final void c(String str, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1032268242);
        int i2 = i | (c0814p2.f(str) ? 4 : 2) | 48;
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            if (str.length() > 0) {
                androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).o;
                c0814p = c0814p2;
                nVar2 = nVar3;
                androidx.compose.material3.Q4.b(str, nVar2, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, i2 & 126, 0, 65528);
            } else {
                c0814p = c0814p2;
                nVar2 = nVar3;
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.modals.e(str, nVar2, i, 5);
        }
    }

    public static final void d(TermUiModel termUiModel, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1381652584);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(termUiModel) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, g0B, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, layoutWeightElement);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            i(0, 2, c0814p, null, termUiModel.a);
            c(termUiModel.b, null, c0814p, 0);
            c0814p.p(true);
            f(termUiModel.c, c0814p, 0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.search.composables.L(termUiModel, i, 1);
        }
    }

    public static final void e(int i, TermUiModel termUiModel, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1057021745);
        int i3 = (c0814p.d(i) ? 4 : 2) | i2 | (c0814p.f(termUiModel) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128);
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = AbstractC0460p.g(qVar, 2, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).e0, androidx.compose.foundation.shape.e.a(12));
            com.quizlet.themes.m.g.s();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarG, com.quizlet.ui.resources.designsystem.generated.j.h);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            if (i == 2) {
                c0814p.X(-1983663299);
                d(termUiModel, c0814p, (i3 >> 3) & 14);
                c0814p.p(false);
            } else {
                c0814p.X(-1983593890);
                b(termUiModel, c0814p, (i3 >> 3) & 14);
                c0814p.p(false);
            }
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.search.composables.A(i, termUiModel, qVar, i2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x006b  */
    /* JADX WARN: Removed duplicated region for block: B:22:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void f(java.lang.String r12, androidx.compose.runtime.InterfaceC0806l r13, int r14) {
        /*
            r5 = r13
            androidx.compose.runtime.p r5 = (androidx.compose.runtime.C0814p) r5
            r13 = 662463702(0x277c64d6, float:3.5026689E-15)
            r5.Z(r13)
            boolean r13 = r5.f(r12)
            r0 = 2
            if (r13 == 0) goto L12
            r13 = 4
            goto L13
        L12:
            r13 = r0
        L13:
            r13 = r13 | r14
            r1 = r13 & 3
            if (r1 != r0) goto L24
            boolean r0 = r5.x()
            if (r0 != 0) goto L1f
            goto L24
        L1f:
            r5.Q()
        L22:
            r0 = r12
            goto L65
        L24:
            if (r12 == 0) goto L22
            int r0 = r12.length()
            if (r0 != 0) goto L2d
            goto L22
        L2d:
            androidx.compose.ui.n r6 = androidx.compose.ui.n.b
            com.quizlet.themes.m r0 = com.quizlet.themes.m.g
            r0.s()
            float r7 = com.quizlet.ui.resources.designsystem.generated.j.h
            r9 = 0
            r10 = 0
            r8 = 0
            r11 = 14
            androidx.compose.ui.q r0 = androidx.compose.foundation.layout.AbstractC0382e.y(r6, r7, r8, r9, r10, r11)
            androidx.compose.ui.q r6 = androidx.compose.ui.platform.N.G(r0, r12)
            float r9 = com.quizlet.themes.m.B
            float r10 = com.quizlet.themes.m.C
            r7 = 0
            r8 = 0
            r11 = 3
            androidx.compose.ui.q r2 = androidx.compose.foundation.layout.K0.n(r6, r7, r8, r9, r10, r11)
            r0 = 2131231498(0x7f08030a, float:1.8079079E38)
            r1 = 0
            androidx.compose.ui.graphics.painter.b r3 = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(r0, r5, r1)
            androidx.compose.ui.graphics.painter.b r4 = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(r0, r5, r1)
            r13 = r13 & 14
            r6 = r13 | 48
            r7 = 32736(0x7fe0, float:4.5873E-41)
            r1 = 0
            r0 = r12
            com.google.android.gms.internal.mlkit_vision_camera.r3.b(r0, r1, r2, r3, r4, r5, r6, r7)
        L65:
            androidx.compose.runtime.o0 r12 = r5.r()
            if (r12 == 0) goto L73
            com.quizlet.explanations.solution.recyclerview.step.h r13 = new com.quizlet.explanations.solution.recyclerview.step.h
            r1 = 4
            r13.<init>(r0, r14, r1)
            r12.d = r13
        L73:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.D0.f(java.lang.String, androidx.compose.runtime.l, int):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:103:0x03b5  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x0337  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x033b  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0358  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x039f  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x03a1  */
    /* JADX WARN: Type inference failed for: r3v1 */
    /* JADX WARN: Type inference failed for: r3v2, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r3v4 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void g(com.quizlet.search.data.term.f r47, int r48, kotlin.jvm.functions.Function2 r49, kotlin.jvm.functions.Function0 r50, androidx.compose.runtime.InterfaceC0806l r51, int r52) {
        /*
            Method dump skipped, instructions count: 1020
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.D0.g(com.quizlet.search.data.term.f, int, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int):void");
    }

    public static final void h(com.quizlet.search.data.term.h hVar, int i, Function2 function2, Function0 function0, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1450510503);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.f(hVar) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.d(i) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p.h(function2) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p.h(function0) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i2 & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            if (hVar instanceof com.quizlet.search.data.term.f) {
                c0814p.X(-1751471726);
                g((com.quizlet.search.data.term.f) hVar, i, function2, function0, c0814p, i3 & 8176);
                c0814p.p(false);
            } else {
                if (!Intrinsics.b(hVar, com.quizlet.search.data.term.g.a)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-1751473280, c0814p, false);
                }
                c0814p.X(-1751466280);
                AbstractC3249r5.a(null, 0L, c0814p, 0, 3);
                c0814p = c0814p;
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4218e(hVar, i, function2, function0, i2, 13);
        }
    }

    public static final void i(int i, int i2, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str) {
        androidx.compose.ui.q qVar2;
        int i3;
        C0814p c0814p;
        androidx.compose.ui.q qVar3;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-190403239);
        int i4 = i | (c0814p2.f(str) ? 4 : 2);
        int i5 = i2 & 2;
        if (i5 != 0) {
            i3 = i4 | 48;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i4 | (c0814p2.f(qVar2) ? 32 : 16);
        }
        if ((i3 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            if (i5 != 0) {
                qVar2 = androidx.compose.ui.n.b;
            }
            if (str.length() > 0) {
                com.quizlet.themes.m.g.s();
                qVar3 = qVar2;
                c0814p = c0814p2;
                androidx.compose.material3.Q4.b(str, AbstractC0382e.y(qVar2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, 7), ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).j, c0814p, i3 & 14, 0, 65528);
            } else {
                c0814p = c0814p2;
                qVar3 = qVar2;
            }
            qVar2 = qVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.m(str, qVar2, i, i2, 8);
        }
    }

    public static final void j(com.quizlet.search.viewmodels.M viewModel, int i, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p;
        int i4;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-438102106);
        if ((((c0814p2.h(viewModel) ? 4 : 2) | i2 | 16) & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            i4 = i;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i2 & 1) == 0 || c0814p2.w()) {
                i3 = AbstractC3205m5.g(c0814p2).a;
            } else {
                c0814p2.Q();
                i3 = i;
            }
            c0814p2.q();
            viewModel.getClass();
            kotlinx.coroutines.E.A(androidx.lifecycle.p0.j(viewModel), viewModel.j, null, new com.quizlet.search.viewmodels.J(viewModel, null), 2);
            com.quizlet.search.data.term.h hVar = (com.quizlet.search.data.term.h) C0776c.m(new kotlinx.coroutines.flow.Z(viewModel.f), c0814p2).getValue();
            c0814p2.X(-825679143);
            boolean zH = c0814p2.h(viewModel);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zH || objI == v) {
                com.quizlet.search.composables.M m = new com.quizlet.search.composables.M(2, viewModel, com.quizlet.search.viewmodels.M.class, "onViewAllTermsClicked", "onViewAllTermsClicked(JJ)V", 0, 0);
                c0814p2.i0(m);
                objI = m;
            }
            kotlin.reflect.f fVar = (kotlin.reflect.f) objI;
            c0814p2.p(false);
            c0814p2.X(-825677262);
            boolean zH2 = c0814p2.h(viewModel);
            Object objI2 = c0814p2.I();
            if (zH2 || objI2 == v) {
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l lVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, viewModel, com.quizlet.search.viewmodels.M.class, "onCloseClicked", "onCloseClicked()V", 0, 27);
                c0814p2.i0(lVar);
                objI2 = lVar;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            i4 = i3;
            h(hVar, i4, (Function2) fVar, (Function0) ((kotlin.reflect.f) objI2), c0814p, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.t(viewModel, i4, i2);
        }
    }

    public static final C0867f k() {
        C0867f c0867f = a;
        if (c0867f != null) {
            return c0867f;
        }
        C0866e c0866e = new C0866e("Outlined.People", 24.0f, 24.0f, 24.0f, 24.0f, 0L, 0, false, 96);
        kotlin.collections.K k = androidx.compose.ui.graphics.vector.I.a;
        androidx.compose.ui.graphics.X x = new androidx.compose.ui.graphics.X(C0861v.b);
        C0868g c0868g = new C0868g(0);
        c0868g.g(9.0f, 13.75f);
        c0868g.c(-2.34f, DefinitionKt.NO_Float_VALUE, -7.0f, 1.17f, -7.0f, 3.5f);
        c0868g.e(2.0f, 19.0f);
        c0868g.d(14.0f);
        c0868g.j(-1.75f);
        c0868g.c(DefinitionKt.NO_Float_VALUE, -2.33f, -4.66f, -3.5f, -7.0f, -3.5f);
        c0868g.b();
        c0868g.g(4.34f, 17.0f);
        c0868g.c(0.84f, -0.58f, 2.87f, -1.25f, 4.66f, -1.25f);
        c0868g.i(3.82f, 0.67f, 4.66f, 1.25f);
        c0868g.e(4.34f, 17.0f);
        c0868g.b();
        c0868g.g(9.0f, 12.0f);
        c0868g.c(1.93f, DefinitionKt.NO_Float_VALUE, 3.5f, -1.57f, 3.5f, -3.5f);
        c0868g.h(10.93f, 5.0f, 9.0f, 5.0f);
        c0868g.h(5.5f, 6.57f, 5.5f, 8.5f);
        c0868g.h(7.07f, 12.0f, 9.0f, 12.0f);
        c0868g.b();
        c0868g.g(9.0f, 7.0f);
        c0868g.c(0.83f, DefinitionKt.NO_Float_VALUE, 1.5f, 0.67f, 1.5f, 1.5f);
        c0868g.h(9.83f, 10.0f, 9.0f, 10.0f);
        c0868g.i(-1.5f, -0.67f, -1.5f, -1.5f);
        c0868g.h(8.17f, 7.0f, 9.0f, 7.0f);
        c0868g.b();
        c0868g.g(16.04f, 13.81f);
        c0868g.c(1.16f, 0.84f, 1.96f, 1.96f, 1.96f, 3.44f);
        c0868g.e(18.0f, 19.0f);
        c0868g.d(4.0f);
        c0868g.j(-1.75f);
        c0868g.c(DefinitionKt.NO_Float_VALUE, -2.02f, -3.5f, -3.17f, -5.96f, -3.44f);
        c0868g.b();
        c0868g.g(15.0f, 12.0f);
        c0868g.c(1.93f, DefinitionKt.NO_Float_VALUE, 3.5f, -1.57f, 3.5f, -3.5f);
        c0868g.h(16.93f, 5.0f, 15.0f, 5.0f);
        c0868g.c(-0.54f, DefinitionKt.NO_Float_VALUE, -1.04f, 0.13f, -1.5f, 0.35f);
        c0868g.c(0.63f, 0.89f, 1.0f, 1.98f, 1.0f, 3.15f);
        c0868g.i(-0.37f, 2.26f, -1.0f, 3.15f);
        c0868g.c(0.46f, 0.22f, 0.96f, 0.35f, 1.5f, 0.35f);
        c0868g.b();
        C0866e.a(c0866e, c0868g.a, x);
        C0867f c0867fB = c0866e.b();
        a = c0867fB;
        return c0867fB;
    }
}
