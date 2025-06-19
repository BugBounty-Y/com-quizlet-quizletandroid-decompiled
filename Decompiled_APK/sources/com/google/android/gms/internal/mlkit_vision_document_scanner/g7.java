package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
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
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.C4757a;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class g7 {
    public static final /* synthetic */ int a = 0;

    public static final void a(com.quizlet.assembly.compose.modals.x modalState, C4757a answerPromptConfiguration, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        Intrinsics.checkNotNullParameter(answerPromptConfiguration, "answerPromptConfiguration");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(238554877);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(modalState) : c0814p.h(modalState) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(answerPromptConfiguration) ? 32 : 16;
        }
        int i3 = i2 | 384;
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            U5.b(modalState, nVar3, false, null, null, null, androidx.compose.runtime.internal.e.e(726055736, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.c(answerPromptConfiguration, 2), c0814p), c0814p, (i3 & 14) | 1572872 | ((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND), 60);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 22, modalState, answerPromptConfiguration, nVar2);
        }
    }

    public static final void b(C4757a c4757a, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        boolean z2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-14997194);
        if (((i | (c0814p.h(c4757a) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).e;
            String strD = AbstractC3106b5.d(c0814p, R.string.test_mode_settings_answer_options_header);
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(strD, qVarY, ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65528);
            mVar.s();
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.test_mode_settings_answer_with_label), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).j, c0814p, 0, 0, 65528);
            mVar.s();
            androidx.compose.ui.q qVarY2 = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            com.quizlet.qutils.string.g gVar = c4757a.g;
            androidx.compose.runtime.X0 x0 = AndroidCompositionLocals_androidKt.b;
            h7.k(gVar.a((Context) c0814p.j(x0)), c4757a.a, qVarY2, c0814p, 0);
            mVar.s();
            androidx.compose.ui.q qVarY3 = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            Context context = (Context) c0814p.j(x0);
            com.quizlet.qutils.string.g gVar2 = c4757a.h;
            h7.k(gVar2.a(context), c4757a.b, qVarY3, c0814p, 0);
            c0814p.X(1021543922);
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar = c4757a.c;
            if (jVar != null) {
                mVar.s();
                z = false;
                h7.k(AbstractC3106b5.d(c0814p, R.string.location), jVar, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, 0);
            } else {
                z = false;
            }
            c0814p.p(z);
            mVar.s();
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.test_mode_settings_prompt_with_label), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).j, c0814p, 0, 0, 65528);
            c0814p = c0814p;
            mVar.s();
            h7.k(c4757a.g.a((Context) c0814p.j(x0)), c4757a.d, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, 0);
            mVar.s();
            h7.k(gVar2.a((Context) c0814p.j(x0)), c4757a.e, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, 0);
            c0814p.X(1021584210);
            com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar2 = c4757a.f;
            if (jVar2 != null) {
                mVar.s();
                z2 = false;
                h7.k(AbstractC3106b5.d(c0814p, R.string.location), jVar2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, 0);
            } else {
                z2 = false;
            }
            c0814p.p(z2);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(c4757a, qVar, i, 29);
        }
    }
}
