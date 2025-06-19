package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import assistantMode.types.QuestionElement;
import assistantMode.types.unions.ImageAttribute;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3721s5;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class m3 {
    public static final void a(int i, D6 d6, Function0 function0, Function1 function1, Function1 function12, InterfaceC0806l interfaceC0806l, int i2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1708510957);
        int i3 = i2 | (c0814p.d(i) ? 4 : 2) | (c0814p.h(d6) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128) | (c0814p.h(function1) ? 2048 : 1024) | (c0814p.h(function12) ? 16384 : 8192);
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarF = AbstractC0460p.f(androidx.compose.ui.n.b, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.n(), androidx.compose.ui.graphics.F.a);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarF);
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
            C0776c.E(c0814p, qVarC, C0914j.d);
            if (d6 instanceof com.quizlet.features.infra.models.flashcards.j) {
                c0814p.X(425361648);
                com.quizlet.features.infra.models.flashcards.j jVar = (com.quizlet.features.infra.models.flashcards.j) d6;
                int i5 = i3 & 14;
                int i6 = i3 << 9;
                o3.b(i, jVar.a, jVar.b, jVar.c, null, function0, function1, function12, c0814p, i5 | (458752 & i6) | (3670016 & i6) | (i6 & 29360128));
                c0814p = c0814p;
                c0814p.p(false);
            } else if (d6 instanceof com.quizlet.features.infra.models.flashcards.b) {
                c0814p.X(425821595);
                j3.a(((com.quizlet.features.infra.models.flashcards.b) d6).a, null, c0814p, 0);
                c0814p.p(false);
            } else if (d6 instanceof com.quizlet.features.infra.models.flashcards.k) {
                c0814p.X(425935551);
                com.quizlet.features.infra.models.flashcards.k kVar = (com.quizlet.features.infra.models.flashcards.k) d6;
                p3.b(kVar.a, kVar.b, null, function0, function12, c0814p, ((i3 << 3) & 7168) | (i3 & 57344));
                c0814p.p(false);
            } else {
                if (!(d6 instanceof com.quizlet.features.infra.models.flashcards.g)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-1510300366, c0814p, false);
                }
                c0814p.X(426228098);
                l3.a(((com.quizlet.features.infra.models.flashcards.g) d6).a, null, function1, c0814p, (i3 >> 3) & 896);
                c0814p.p(false);
            }
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i(i, d6, function0, function1, function12, i2);
        }
    }

    public static final void b(int i, com.quizlet.features.infra.models.flashcards.f frontData, com.quizlet.features.infra.models.flashcards.f backData, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function1 function1, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        androidx.compose.ui.q qVar2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(frontData, "frontData");
        Intrinsics.checkNotNullParameter(backData, "backData");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-138164736);
        if ((i2 & 6) == 0) {
            i3 = (c0814p2.d(i) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p2.h(frontData) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p2.h(backData) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            qVar2 = qVar;
            i3 |= c0814p2.f(qVar2) ? 2048 : 1024;
        } else {
            qVar2 = qVar;
        }
        if ((i2 & 24576) == 0) {
            i3 |= c0814p2.h(function0) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            i3 |= c0814p2.h(function02) ? 131072 : 65536;
        }
        if ((1572864 & i2) == 0) {
            i3 |= c0814p2.h(function1) ? 1048576 : 524288;
        }
        if ((599187 & i3) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            c0814p2.X(-585770038);
            Object objI = c0814p2.I();
            if (objI == v) {
                objI = C0776c.z(com.quizlet.assembly.compose.components.flashcards.a.d);
                c0814p2.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            c0814p2.p(false);
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            com.quizlet.assembly.compose.components.flashcards.d dVar = i == 0 ? com.quizlet.assembly.compose.components.flashcards.d.b : com.quizlet.assembly.compose.components.flashcards.d.a;
            com.quizlet.assembly.compose.components.flashcards.b bVar = (com.quizlet.assembly.compose.components.flashcards.b) interfaceC0773a0.getValue();
            com.quizlet.ui.compose.util.b bVar2 = new com.quizlet.ui.compose.util.b();
            c0814p2.X(-585737345);
            boolean z = (458752 & i3) == 131072;
            Object objI2 = c0814p2.I();
            if (z || objI2 == v) {
                objI2 = new com.quizlet.features.flashcards.views.composables.f(function02, interfaceC0773a0, 1);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3721s5.a(bVar, qVar2, dVar, bVar2, 0L, null, null, (Function1) objI2, androidx.compose.runtime.internal.e.e(-1661807054, new com.quizlet.features.questiontypes.selfassessment.ui.d(backData, i, function0, function1), c0814p2), androidx.compose.runtime.internal.e.e(-1775417549, new com.quizlet.features.questiontypes.selfassessment.ui.d(i, frontData, function0, function1), c0814p2), 0, c0814p, 905969664 | ((i3 >> 6) & ContentType.LONG_FORM_ON_DEMAND), 1136);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.links.j(i, frontData, backData, qVar, function0, function02, function1, i2);
        }
    }

    public static final String c(assistantMode.refactored.types.d question) {
        Intrinsics.checkNotNullParameter(question, "question");
        return assistantMode.refactored.serialization.a.a.c(assistantMode.refactored.types.d.Companion.serializer(), question);
    }

    public static final boolean d(QuestionElement questionElement) {
        Intrinsics.checkNotNullParameter(questionElement, "<this>");
        List list = questionElement.a;
        if (list != null && list.isEmpty()) {
            return false;
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            if (((assistantMode.types.unions.a) it2.next()) instanceof ImageAttribute) {
                return true;
            }
        }
        return false;
    }
}
