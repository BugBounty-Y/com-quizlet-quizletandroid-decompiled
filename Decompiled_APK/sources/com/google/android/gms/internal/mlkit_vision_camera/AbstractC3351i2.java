package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.generated.enums.EnumC4501m0;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.i2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3351i2 {
    public static final void a(com.quizlet.features.practicetest.results.data.e userAnswer, com.quizlet.features.practicetest.results.data.e correctAnswer, kotlinx.collections.immutable.e unselectedOptions, EnumC4501m0 grade, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        androidx.compose.ui.n nVar;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(userAnswer, "userAnswer");
        Intrinsics.checkNotNullParameter(correctAnswer, "correctAnswer");
        Intrinsics.checkNotNullParameter(unselectedOptions, "unselectedOptions");
        Intrinsics.checkNotNullParameter(grade, "grade");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1821329532);
        if (((i | (c0814p2.f(userAnswer) ? 4 : 2) | (c0814p2.f(correctAnswer) ? 32 : 16) | (c0814p2.f(unselectedOptions) ? 256 : 128) | (c0814p2.f(grade) ? 2048 : 1024) | (c0814p2.f(qVar) ? 16384 : 8192)) & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i2 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, bA, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p2, i2, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            int i3 = com.quizlet.features.practicetest.results.composables.a.a[grade.ordinal()];
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            if (i3 == 1) {
                z = false;
                nVar = nVar2;
                c0814p2.X(582330388);
                AbstractC3347h2.a(userAnswer.a, null, 0L, 0L, userAnswer.b, c0814p2, 0, 14);
                c0814p = c0814p2;
                c0814p.p(false);
            } else if (i3 == 2) {
                c0814p2.X(582623741);
                androidx.compose.runtime.B b = com.quizlet.themes.g.a;
                z = false;
                AbstractC3347h2.a(correctAnswer.a, null, ((com.quizlet.themes.b) c0814p2.j(b)).b.f(), ((com.quizlet.themes.b) c0814p2.j(b)).b.e(), correctAnswer.b, c0814p2, 0, 2);
                c0814p = c0814p2;
                com.quizlet.themes.m.g.s();
                nVar = nVar2;
                AbstractC3359k2.a(0, 0, c0814p, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), userAnswer.a, userAnswer.b);
                c0814p.p(false);
            } else if (i3 == 3) {
                c0814p2.X(583359805);
                R1.c(0, 2, c0814p2, null, AbstractC3106b5.d(c0814p2, R.string.practice_test_results_unanswered));
                com.quizlet.themes.m.g.s();
                c0814p = c0814p2;
                AbstractC3363l2.a(0, 0, c0814p, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), correctAnswer.a, correctAnswer.b);
                c0814p.p(false);
                nVar = nVar2;
                z = false;
            } else {
                if (i3 != 4) {
                    throw com.google.android.gms.measurement.internal.Z.j(-1228141694, c0814p2, false);
                }
                c0814p2.X(583848520);
                c0814p2.p(false);
                z = false;
                c0814p = c0814p2;
                nVar = nVar2;
            }
            c0814p.X(-1228088937);
            Iterator<E> it2 = unselectedOptions.iterator();
            while (it2.hasNext()) {
                com.quizlet.features.practicetest.results.data.e eVar = (com.quizlet.features.practicetest.results.data.e) it2.next();
                com.quizlet.themes.m.g.s();
                androidx.compose.ui.n nVar3 = nVar;
                androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
                String str = eVar.a;
                androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
                C0814p c0814p3 = c0814p;
                AbstractC3343g2.a(str, ((com.quizlet.themes.b) c0814p.j(b2)).s(), ((com.quizlet.themes.b) c0814p.j(b2)).s(), qVarY, null, null, eVar.b, null, c0814p3, 0, 48);
                c0814p = c0814p3;
                nVar = nVar3;
            }
            c0814p.p(z);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(userAnswer, correctAnswer, unselectedOptions, grade, qVar, i);
        }
    }

    public static void b(String key, StringBuilder sb) {
        Intrinsics.checkNotNullParameter(sb, "<this>");
        Intrinsics.checkNotNullParameter(key, "key");
        sb.append('\"');
        int length = key.length();
        for (int i = 0; i < length; i++) {
            char cCharAt = key.charAt(i);
            if (cCharAt == '\n') {
                sb.append("%0A");
            } else if (cCharAt == '\r') {
                sb.append("%0D");
            } else if (cCharAt == '\"') {
                sb.append("%22");
            } else {
                sb.append(cCharAt);
            }
        }
        sb.append('\"');
    }
}
