package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.vector.C0867f;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3253s0;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.s0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3253s0 {
    public static C0867f a;

    public static final void a(DiagramData diagramData, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        DiagramData diagramData2;
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1591774626);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(diagramData) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            diagramData2 = diagramData;
            function02 = function0;
        } else {
            com.quizlet.diagrams.b[] bVarArr = {com.quizlet.diagrams.b.b};
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.q();
            diagramData2 = diagramData;
            function02 = function0;
            com.google.android.gms.internal.mlkit_vision_document_scanner.L6.a(diagramData2, AbstractC0382e.w(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, 1), bVarArr, true, null, null, function02, null, c0814p, (i2 & 14) | 3072 | ((i2 << 15) & 3670016), 176);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(diagramData2, function02, i, 5);
        }
    }

    public static final void b(D6 viewState, boolean z, boolean z2, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function1 function1, Function0 function03, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar;
        boolean z3;
        Intrinsics.checkNotNullParameter(viewState, "viewState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-422750201);
        int i2 = i | (c0814p.h(viewState) ? 4 : 2) | (c0814p.g(z) ? 32 : 16) | (c0814p.g(z2) ? 256 : 128) | (c0814p.h(function0) ? 16384 : 8192) | (c0814p.h(function02) ? 131072 : 65536) | (c0814p.h(function1) ? 1048576 : 524288) | (c0814p.h(function03) ? 8388608 : 4194304);
        if ((4793491 & i2) == 4793490 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVar, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.n(), androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarF, f, DefinitionKt.NO_Float_VALUE, 2);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, gVar, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarW);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            boolean zC = viewState.c();
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            mVar.q();
            g(z2, zC, function0, z, function02, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, ((i2 >> 6) & 910) | ((i2 << 6) & 7168) | ((i2 >> 3) & 57344));
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.C.a(nVar2, 1.0f));
            if (viewState instanceof com.quizlet.features.infra.models.flashcards.b) {
                c0814p.X(1448263016);
                a(((com.quizlet.features.infra.models.flashcards.b) viewState).a, function03, c0814p, (i2 >> 18) & ContentType.LONG_FORM_ON_DEMAND);
                c0814p.p(false);
            } else if (viewState instanceof com.quizlet.features.infra.models.flashcards.g) {
                c0814p.X(1448267887);
                c((i2 >> 18) & ContentType.LONG_FORM_ON_DEMAND, 4, c0814p, null, ((com.quizlet.features.infra.models.flashcards.g) viewState).a.a(), function03);
                c0814p.p(false);
            } else if (viewState instanceof com.quizlet.features.infra.models.flashcards.j) {
                c0814p.X(1448273106);
                e((com.quizlet.features.infra.models.flashcards.j) viewState, function1, function03, c0814p, (i2 >> 15) & 1008);
                c0814p.p(false);
            } else {
                if (!(viewState instanceof com.quizlet.features.infra.models.flashcards.k)) {
                    throw com.google.android.gms.measurement.internal.Z.j(1448262147, c0814p, false);
                }
                c0814p.X(1448279373);
                mVar.q();
                int i4 = (i2 >> 15) & 1008;
                nVar = nVar2;
                z3 = true;
                f(((com.quizlet.features.infra.models.flashcards.k) viewState).a, function1, function03, AbstractC0382e.w(nVar2, DefinitionKt.NO_Float_VALUE, f, 1), c0814p, i4);
                c0814p.p(false);
                AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.C.a(nVar, 1.0f));
                c0814p.p(z3);
            }
            nVar = nVar2;
            z3 = true;
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.C.a(nVar, 1.0f));
            c0814p.p(z3);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.views.composables.c(viewState, z, z2, qVar, function0, function02, function1, function03, i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0060  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00bd  */
    /* JADX WARN: Removed duplicated region for block: B:52:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(int r16, int r17, androidx.compose.runtime.InterfaceC0806l r18, androidx.compose.ui.q r19, java.lang.String r20, kotlin.jvm.functions.Function0 r21) {
        /*
            r4 = r16
            r1 = r20
            r2 = r21
            r11 = r18
            androidx.compose.runtime.p r11 = (androidx.compose.runtime.C0814p) r11
            r0 = -305830135(0xffffffffedc56709, float:-7.6366386E27)
            r11.Z(r0)
            r0 = r4 & 6
            if (r0 != 0) goto L1f
            boolean r0 = r11.f(r1)
            if (r0 == 0) goto L1c
            r0 = 4
            goto L1d
        L1c:
            r0 = 2
        L1d:
            r0 = r0 | r4
            goto L20
        L1f:
            r0 = r4
        L20:
            r3 = r4 & 48
            r5 = 32
            if (r3 != 0) goto L31
            boolean r3 = r11.h(r2)
            if (r3 == 0) goto L2e
            r3 = r5
            goto L30
        L2e:
            r3 = 16
        L30:
            r0 = r0 | r3
        L31:
            r3 = r17 & 4
            if (r3 == 0) goto L3a
            r0 = r0 | 384(0x180, float:5.38E-43)
        L37:
            r6 = r19
            goto L4c
        L3a:
            r6 = r4 & 384(0x180, float:5.38E-43)
            if (r6 != 0) goto L37
            r6 = r19
            boolean r7 = r11.f(r6)
            if (r7 == 0) goto L49
            r7 = 256(0x100, float:3.59E-43)
            goto L4b
        L49:
            r7 = 128(0x80, float:1.8E-43)
        L4b:
            r0 = r0 | r7
        L4c:
            r7 = r0 & 147(0x93, float:2.06E-43)
            r8 = 146(0x92, float:2.05E-43)
            if (r7 != r8) goto L5e
            boolean r7 = r11.x()
            if (r7 != 0) goto L59
            goto L5e
        L59:
            r11.Q()
            r3 = r6
            goto Lb7
        L5e:
            if (r3 == 0) goto L63
            androidx.compose.ui.n r3 = androidx.compose.ui.n.b
            goto L64
        L63:
            r3 = r6
        L64:
            if (r1 == 0) goto Lb7
            r6 = 5
            r7 = 0
            r8 = 48
            com.quizlet.assembly.compose.modals.x r14 = com.google.android.gms.internal.mlkit_vision_document_scanner.Y5.h(r7, r7, r11, r8, r6)
            kotlin.Unit r6 = kotlin.Unit.a
            r8 = 1411024453(0x541a8645, float:2.6547105E12)
            r11.X(r8)
            boolean r8 = r11.h(r14)
            r9 = r0 & 112(0x70, float:1.57E-43)
            if (r9 != r5) goto L80
            r5 = 1
            goto L81
        L80:
            r5 = r7
        L81:
            r5 = r5 | r8
            java.lang.Object r8 = r11.I()
            r15 = 0
            if (r5 != 0) goto L8d
            androidx.compose.runtime.V r5 = androidx.compose.runtime.C0804k.a
            if (r8 != r5) goto L95
        L8d:
            com.quizlet.features.flashcards.views.composables.d r8 = new com.quizlet.features.flashcards.views.composables.d
            r8.<init>(r14, r2, r15)
            r11.i0(r8)
        L95:
            kotlin.jvm.functions.Function2 r8 = (kotlin.jvm.functions.Function2) r8
            r11.p(r7)
            androidx.compose.ui.q r5 = androidx.compose.ui.input.pointer.v.a(r3, r6, r8)
            java.lang.String r6 = "imageOnly"
            androidx.compose.ui.q r7 = androidx.compose.ui.platform.N.G(r5, r6)
            r0 = r0 & 14
            r12 = r0 | 48
            r9 = 0
            r10 = 0
            r6 = 0
            r8 = 0
            r13 = 2040(0x7f8, float:2.859E-42)
            r5 = r1
            com.google.android.gms.internal.mlkit_vision_camera.r3.a(r5, r6, r7, r8, r9, r10, r11, r12, r13)
            r0 = r0 | 512(0x200, float:7.17E-43)
            com.google.android.gms.internal.mlkit_vision_document_scanner.Z5.c(r1, r15, r14, r11, r0)
        Lb7:
            androidx.compose.runtime.o0 r7 = r11.r()
            if (r7 == 0) goto Lc7
            com.quizlet.assembly.compose.buttons.f0 r0 = new com.quizlet.assembly.compose.buttons.f0
            r6 = 1
            r5 = r17
            r0.<init>(r1, r2, r3, r4, r5, r6)
            r7.d = r0
        Lc7:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3253s0.c(int, int, androidx.compose.runtime.l, androidx.compose.ui.q, java.lang.String, kotlin.jvm.functions.Function0):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void d(String query, SearchType searchType, androidx.compose.ui.n nVar, float f, com.quizlet.search.viewmodels.x xVar, kotlin.jvm.functions.c cVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        boolean z;
        androidx.compose.foundation.lazy.grid.A a2;
        int i2;
        C0814p c0814p;
        androidx.compose.ui.n nVar3;
        Intrinsics.checkNotNullParameter(query, "query");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(47901467);
        int i3 = i | (c0814p2.f(query) ? 4 : 2) | (c0814p2.f(searchType) ? 32 : 16) | 384 | (c0814p2.c(f) ? 2048 : 1024) | (c0814p2.h(xVar) ? 16384 : 8192) | (c0814p2.h(cVar) ? 131072 : 65536);
        if ((74899 & i3) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            nVar3 = nVar;
        } else {
            c0814p2.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 == 0 || c0814p2.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p2.Q();
                nVar2 = nVar;
            }
            c0814p2.q();
            androidx.compose.foundation.lazy.grid.A a3 = androidx.compose.foundation.lazy.grid.B.a(0, c0814p2, 3);
            int iD = AbstractC3236q0.d(c0814p2);
            androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.K0.c(nVar2, 1.0f).g(androidx.compose.foundation.layout.K0.b);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.foundation.layout.A0 a0C = Q5.c(new androidx.compose.foundation.layout.A0(f2, f2, f2, f2), f);
            C0380d c0380d = AbstractC0398m.a;
            mVar.s();
            C0392j c0392jG = AbstractC0398m.g(f2);
            mVar.s();
            C0392j c0392jG2 = AbstractC0398m.g(f2);
            c0814p2.X(-2005868852);
            boolean zH = ((i3 & 14) == 4) | c0814p2.h(xVar);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                z = false;
                objI = new com.quizlet.search.composables.r(xVar, query, 0 == true ? 1 : 0);
                c0814p2.i0(objI);
            } else {
                z = false;
            }
            Function0 function0 = (Function0) objI;
            c0814p2.p(z);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-2142618186, new com.quizlet.search.composables.q(f, 1), c0814p2);
            c0814p2.X(-2005847757);
            boolean zD = ((i3 & 458752) == 131072) | c0814p2.d(iD) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p2.f(a3) | c0814p2.h(xVar);
            Object objI2 = c0814p2.I();
            if (zD || objI2 == v) {
                a2 = a3;
                i2 = iD;
                objI2 = new com.quizlet.quizletandroid.ui.globalnav.composable.d(i2, cVar, searchType, a2, xVar, 9);
                c0814p2.i0(objI2);
            } else {
                a2 = a3;
                i2 = iD;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3266t5.b(function0, qVarG, 0L, i2, a0C, c0392jG, c0392jG2, a2, dVarE, null, (Function2) objI2, c0814p, 100663296, 516);
            nVar3 = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.search.composables.p(query, searchType, nVar3, f, xVar, cVar, i, 1);
        }
    }

    public static final void e(com.quizlet.features.infra.models.flashcards.j jVar, Function1 function1, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function12;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-599702865);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(jVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            function12 = function1;
            i2 |= c0814p.h(function12) ? 32 : 16;
        } else {
            function12 = function1;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, gVar, c0814p, 48);
            int i3 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            String strA = jVar.b.a();
            androidx.compose.ui.q qVarA = androidx.compose.foundation.layout.C.a(nVar, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            c((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND, 0, c0814p, AbstractC0382e.y(qVarA, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), strA, function0);
            androidx.compose.ui.q qVarA2 = androidx.compose.foundation.layout.C.a(nVar, 1.0f);
            mVar.q();
            f(jVar.a, function12, function0, AbstractC0382e.w(qVarA2, DefinitionKt.NO_Float_VALUE, f, 1), c0814p, i2 & 1008);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 10, jVar, function1, function0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:57:0x0142  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0146  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x0161  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0180  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0182  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x018e  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x0190  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0198  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x019d  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x01c5  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x01d1  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0221  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void f(com.quizlet.studiablemodels.StudiableText r25, kotlin.jvm.functions.Function1 r26, kotlin.jvm.functions.Function0 r27, androidx.compose.ui.q r28, androidx.compose.runtime.InterfaceC0806l r29, int r30) {
        /*
            Method dump skipped, instructions count: 635
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3253s0.f(com.quizlet.studiablemodels.StudiableText, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function0, androidx.compose.ui.q, androidx.compose.runtime.l, int):void");
    }

    public static final void g(final boolean z, final boolean z2, final Function0 function0, final boolean z3, final Function0 function02, final androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(484765422);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.g(z3) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function02) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.f(qVar) ? 131072 : 65536;
        }
        if ((74899 & i2) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i3 = c0814p.P;
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
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            c0814p.X(-57255554);
            if (z2) {
                AbstractC3293x0.c(z, null, function0, c0814p, i2 & 910);
            }
            c0814p.p(false);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            AbstractC0382e.f(c0814p, new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true));
            AbstractC3301y0.b(z3, null, function02, c0814p, ((i2 >> 6) & 896) | ((i2 >> 9) & 14));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.flashcards.views.composables.b
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    Function0 function03 = function02;
                    q qVar2 = qVar;
                    AbstractC3253s0.g(z, z2, function0, z3, function03, qVar2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }
}
