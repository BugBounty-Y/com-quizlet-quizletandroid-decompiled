package com.google.android.gms.internal.mlkit_vision_common;

import android.net.Uri;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
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
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3721s5;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.StudiableImage;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class A {
    public static final void a(com.quizlet.features.infra.models.a aVar, StudiableImage studiableImage, Function0 function0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        StudiableImage studiableImage2;
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1432795560);
        int i4 = i | (c0814p.f(aVar) ? 4 : 2);
        int i5 = i2 & 2;
        if (i5 != 0) {
            i3 = i4 | 48;
            studiableImage2 = studiableImage;
        } else {
            studiableImage2 = studiableImage;
            i3 = i4 | (c0814p.h(studiableImage2) ? 32 : 16);
        }
        int i6 = i3 | (c0814p.h(function0) ? 256 : 128);
        if ((i6 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i5 != 0) {
                studiableImage2 = null;
            }
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(androidx.compose.foundation.layout.K0.c, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.n(), androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m.g.u();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarF, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, 1);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i7 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            d(aVar, androidx.compose.foundation.layout.C.a(nVar, 1.0f), studiableImage2, c0814p, (i6 & 14) | ((i6 << 3) & 896));
            c0814p.X(-207835589);
            boolean z = (i6 & 896) == 256;
            Object objI = c0814p.I();
            if (z || objI == v) {
                objI = new com.quizlet.features.setpage.composable.a(7, function0);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            b(0, c0814p, null, (Function0) objI);
            c0814p.p(true);
        }
        StudiableImage studiableImage3 = studiableImage2;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(aVar, studiableImage3, function0, i, i2);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.n nVar, Function0 function0) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-115240857);
        int i2 = i | 6 | (c0814p.h(function0) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            nVar2 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar2, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            mVar.w();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarC, f, DefinitionKt.NO_Float_VALUE, f, com.quizlet.ui.resources.designsystem.generated.j.f, 2);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.f, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarY);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar2, "LaunchFlashcardsIcon");
            mVar.h();
            float f2 = com.quizlet.ui.resources.designsystem.generated.h.g;
            androidx.compose.ui.q qVarD = androidx.compose.foundation.layout.K0.d(qVarG, f2);
            mVar.h();
            androidx.compose.ui.q qVarO = androidx.compose.foundation.layout.K0.o(qVarD, f2);
            c0814p.X(188912153);
            boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            if (z || objI == v) {
                objI = new com.quizlet.features.setpage.composable.a(8, function0);
                c0814p.i0(objI);
            }
            Function0 onClick = (Function0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(188914435, c0814p, false);
            if (objG == v) {
                objG = androidx.compose.animation.d0.i(c0814p);
            }
            androidx.compose.foundation.interaction.l interactionSource = (androidx.compose.foundation.interaction.l) objG;
            c0814p.p(false);
            Intrinsics.checkNotNullParameter(qVarO, "<this>");
            Intrinsics.checkNotNullParameter(onClick, "onClick");
            Intrinsics.checkNotNullParameter(interactionSource, "interactionSource");
            androidx.compose.ui.q qVarK = AbstractC0460p.k(qVarO, interactionSource, null, false, null, onClick, 28);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            c0814p.X(-280740818);
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_sys_fullscreen, c0814p, 0);
            c0814p.p(false);
            androidx.compose.material3.D1.a(bVarA, null, qVarK, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).k, c0814p, 48, 0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.A(nVar2, function0, i, 2);
        }
    }

    public static final void c(com.quizlet.assembly.compose.components.flashcards.b cardFace, com.quizlet.features.setpage.studypreview.data.a cardData, androidx.compose.ui.q qVar, Function1 function1, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(cardFace, "cardFace");
        Intrinsics.checkNotNullParameter(cardData, "cardData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1967684279);
        int i2 = i | (c0814p.f(cardFace) ? 4 : 2) | (c0814p.h(cardData) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128) | (c0814p.h(function1) ? 2048 : 1024) | (c0814p.h(function0) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar, "Flashcard");
            com.quizlet.assembly.compose.components.flashcards.d dVar = com.quizlet.assembly.compose.components.flashcards.d.a;
            com.quizlet.ui.compose.util.b bVar = new com.quizlet.ui.compose.util.b();
            androidx.compose.material3.Y yP = androidx.compose.material3.Z1.p(com.quizlet.themes.m.j, 62);
            c0814p.X(-660371466);
            boolean z = (i2 & 7168) == 2048;
            Object objI = c0814p.I();
            if (z || objI == v) {
                objI = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.l(13, function1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3721s5.a(cardFace, qVarG, dVar, bVar, 0L, null, yP, (Function1) objI, androidx.compose.runtime.internal.e.e(1361177431, new com.quizlet.features.setpage.studypreview.composables.a(cardData, function0, 0), c0814p), androidx.compose.runtime.internal.e.e(-910290314, new com.quizlet.features.setpage.studypreview.composables.a(cardData, function0, 1), c0814p), 0, c0814p, 906166656 | (i2 & 14), 1040);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(cardFace, cardData, qVar, function1, function0, i);
        }
    }

    public static final void d(com.quizlet.features.infra.models.a aVar, androidx.compose.ui.q qVar, StudiableImage studiableImage, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.foundation.layout.I0 i0;
        boolean z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1601887887);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(aVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(studiableImage) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = qVar.g(androidx.compose.foundation.layout.K0.c);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarG, f, DefinitionKt.NO_Float_VALUE, 2);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
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
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.foundation.layout.I0 i02 = androidx.compose.foundation.layout.I0.a;
            String str = aVar.d;
            if (str == null) {
                str = aVar.a;
            }
            c0814p.X(-475390101);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (str == null || str.length() == 0) {
                i0 = i02;
                z = true;
            } else {
                mVar.q();
                i0 = i02;
                z = true;
                AbstractC0382e.a(i02.a(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f, true), null, androidx.compose.runtime.internal.e.e(358354300, new com.quizlet.features.questiontypes.mcq.ui.c(2, str, aVar), c0814p), c0814p, 3072, 6);
            }
            c0814p.p(false);
            c0814p.X(-475359443);
            if (studiableImage != null) {
                androidx.compose.ui.q qVarG2 = androidx.compose.ui.platform.N.G(nVar, "AsyncImage");
                mVar.s();
                com.google.android.gms.internal.mlkit_vision_camera.r3.a(studiableImage.a(), null, i0.a(AbstractC0382e.y(qVarG2, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), 0.5f, z), null, null, null, c0814p, 48, 2040);
                c0814p = c0814p;
            }
            c0814p.p(false);
            c0814p.p(z);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(aVar, qVar, studiableImage, i);
        }
    }

    public static boolean e(Uri uri) {
        return uri != null && "content".equals(uri.getScheme()) && "media".equals(uri.getAuthority());
    }
}
