package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3164i0;
import com.quizlet.studiablemodels.StudiableImage;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class L2 {
    public static final void a(com.quizlet.features.questiontypes.data.d dVar, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function0 function04;
        long jE;
        androidx.compose.runtime.V v;
        int i3;
        boolean z;
        StudiableImage studiableImage;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(521504851);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(dVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            function04 = function0;
            i2 |= c0814p.h(function04) ? 256 : 128;
        } else {
            function04 = function0;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function02) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function03) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v2 = C0804k.a;
            com.quizlet.features.infra.models.a aVar = dVar != null ? dVar.a : null;
            String strA = (dVar == null || (studiableImage = dVar.b) == null) ? null : studiableImage.a();
            if (((Boolean) function04.invoke()).booleanValue()) {
                c0814p.X(-1568742635);
                jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).e;
                c0814p.p(false);
            } else {
                c0814p.X(-1568692663);
                jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
                c0814p.p(false);
            }
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.m, c0814p, 6);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            c0814p.X(1018144296);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (aVar != null) {
                androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(androidx.compose.ui.platform.N.G(nVar, "promptText"), 1.0f);
                com.quizlet.themes.m.g.s();
                androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarC3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, 7);
                c0814p.X(-1763921642);
                boolean z2 = (i2 & 7168) == 2048;
                Object objI = c0814p.I();
                if (z2 || objI == v2) {
                    objI = new com.braze.support.u(27, function02);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                v = v2;
                z = false;
                i3 = 16384;
                AbstractC3164i0.c(aVar.c, aVar.a, aVar.d, aVar.b, AbstractC0460p.l(qVarY, false, null, (Function0) objI, 7), ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).n, jE, 0, 0, null, null, c0814p, 0, 0, 1920);
                c0814p = c0814p;
                Unit unit = Unit.a;
            } else {
                v = v2;
                i3 = 16384;
                z = false;
            }
            c0814p.p(z);
            c0814p.X(1018165077);
            if (strA != null && !StringsKt.O(strA)) {
                androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "promptImage");
                com.quizlet.themes.m.g.s();
                androidx.compose.ui.q qVarY2 = AbstractC0382e.y(qVarG, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, 7);
                c0814p.X(1018172632);
                boolean z3 = (i2 & 57344) == i3 ? true : z;
                Object objI2 = c0814p.I();
                if (z3 || objI2 == v) {
                    objI2 = new com.braze.support.u(28, function03);
                    c0814p.i0(objI2);
                }
                c0814p.p(z);
                r3.a(strA, null, AbstractC0460p.l(qVarY2, z, null, (Function0) objI2, 7), null, null, null, c0814p, 48, 2040);
            }
            c0814p.p(z);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(dVar, qVar, function0, function02, function03, i, 9);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0095  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x009a A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0048 A[ADDED_TO_REGION, REMOVE, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.util.ArrayList b(assistantMode.refactored.types.StudiableData r13, java.util.List r14, java.util.List r15) {
        /*
            assistantMode.enums.k r0 = assistantMode.enums.k.f
            java.lang.String r1 = "studiableData"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r13, r1)
            java.lang.String r1 = "questionType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            java.lang.String r1 = "promptSides"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r14, r1)
            java.lang.String r1 = "answerSides"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r15, r1)
            r1 = 1
            r2 = 0
            assistantMode.utils.h r13 = assistantMode.refactored.shims.b.b(r13, r1, r2)
            java.util.List r3 = r13.a
            java.util.ArrayList r4 = new java.util.ArrayList
            r4.<init>()
            java.util.Iterator r3 = r3.iterator()
        L27:
            boolean r5 = r3.hasNext()
            if (r5 == 0) goto Lbb
            java.lang.Object r5 = r3.next()
            assistantMode.types.a r5 = (assistantMode.types.C1454a) r5
            java.util.Iterator r6 = r14.iterator()
        L37:
            boolean r7 = r6.hasNext()
            r8 = 0
            if (r7 == 0) goto La2
            java.lang.Object r7 = r6.next()
            assistantMode.enums.m r7 = (assistantMode.enums.m) r7
            java.util.Iterator r9 = r15.iterator()
        L48:
            boolean r10 = r9.hasNext()
            if (r10 == 0) goto L37
            java.lang.Object r10 = r9.next()
            assistantMode.enums.m r10 = (assistantMode.enums.m) r10
            int r11 = r7.ordinal()
            r12 = 2
            if (r11 == 0) goto L72
            if (r11 == r1) goto L72
            if (r11 != r12) goto L6c
            kotlin.u r11 = r5.l
            java.lang.Object r11 = r11.getValue()
            assistantMode.refactored.modelTypes.DiagramShapeValue r11 = (assistantMode.refactored.modelTypes.DiagramShapeValue) r11
            if (r11 == 0) goto L6a
            goto L72
        L6a:
            r11 = r8
            goto L73
        L6c:
            kotlin.NoWhenBranchMatchedException r13 = new kotlin.NoWhenBranchMatchedException
            r13.<init>()
            throw r13
        L72:
            r11 = r1
        L73:
            if (r11 == 0) goto L92
            int r11 = r10.ordinal()
            if (r11 == 0) goto L90
            if (r11 == r1) goto L90
            if (r11 != r12) goto L8a
            kotlin.u r11 = r5.l
            java.lang.Object r11 = r11.getValue()
            assistantMode.refactored.modelTypes.DiagramShapeValue r11 = (assistantMode.refactored.modelTypes.DiagramShapeValue) r11
            if (r11 == 0) goto L92
            goto L90
        L8a:
            kotlin.NoWhenBranchMatchedException r13 = new kotlin.NoWhenBranchMatchedException
            r13.<init>()
            throw r13
        L90:
            r11 = r1
            goto L93
        L92:
            r11 = r8
        L93:
            if (r10 == r7) goto L97
            r12 = r1
            goto L98
        L97:
            r12 = r8
        L98:
            if (r11 == 0) goto L48
            if (r12 == 0) goto L48
            assistantMode.types.d r6 = new assistantMode.types.d
            r6.<init>(r5, r7, r10)
            goto La3
        La2:
            r6 = r2
        La3:
            if (r6 != 0) goto La7
            r5 = r2
            goto Lb4
        La7:
            assistantMode.types.B r5 = new assistantMode.types.B
            r5.<init>(r6)
            com.google.android.gms.internal.mlkit_vision_camera.Q2 r5 = com.google.android.gms.internal.mlkit_vision_camera.O2.b(r0, r5, r13, r8)
            assistantMode.refactored.types.d r5 = r5.d()
        Lb4:
            if (r5 == 0) goto L27
            r4.add(r5)
            goto L27
        Lbb:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.L2.b(assistantMode.refactored.types.StudiableData, java.util.List, java.util.List):java.util.ArrayList");
    }
}
