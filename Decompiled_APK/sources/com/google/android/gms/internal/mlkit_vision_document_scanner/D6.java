package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.AbstractC0809m0;
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
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3274u5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D6;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.data.model.EssayInfo;
import com.quizlet.data.model.EssayItem;
import com.quizlet.data.model.FlashcardsInfo;
import com.quizlet.data.model.FlashcardsTermDefinitionCard;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.data.model.OutlineMarkdownInfo;
import com.quizlet.data.model.ReviewSheetInfo;
import com.quizlet.data.model.TitleInfo;
import com.quizlet.data.model.User;
import com.quizlet.features.achievements.ui.composables.C4214a;
import com.quizlet.features.infra.studysetting.data.GradingSettingsValues;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import com.quizlet.shared.models.notes.EssayPromptItem;
import com.quizlet.shared.models.notes.FlashcardItem;
import com.quizlet.shared.models.notes.StudyNoteArtifactInfo$EssayPrompts;
import com.quizlet.shared.models.notes.StudyNoteArtifactInfo$Flashcards;
import com.quizlet.shared.models.notes.StudyNoteArtifactInfo$OutlineMarkdown;
import com.quizlet.shared.models.notes.StudyNoteArtifactInfo$ReviewSheet;
import com.quizlet.shared.models.notes.StudyNoteArtifactInfo$Title;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.WeakHashMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class D6 {
    public static final void a(boolean z, boolean z2, boolean z3, Function1 function1, Function1 function12, Function1 function13, String str, String str2, boolean z4, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1280917088);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z3) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function1) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function12) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function13) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.f(str) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.f(str2) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i2 |= c0814p.g(z4) ? 67108864 : 33554432;
        }
        if ((805306368 & i) == 0) {
            i2 |= c0814p.f(qVar) ? 536870912 : 268435456;
        }
        int i3 = i2;
        if ((i3 & 306783379) == 306783378 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            G6.c(AbstractC3106b5.d(c0814p, R.string.assistant_settings_group_answer_sides), null, c0814p, 0);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.u();
            int i5 = i3 >> 3;
            H6.a(str, z, function1, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "answerWithTermTag", null, 0L, c0814p, (i5 & 896) | ((i3 >> 18) & 14) | 24576 | ((i3 << 3) & ContentType.LONG_FORM_ON_DEMAND), 96);
            c0814p.X(-132017466);
            if (!z4) {
                H6.a(str2, z2, function12, null, "answerWithDefinitionTag", null, 0L, c0814p, ((i3 >> 21) & 14) | 24576 | (i3 & ContentType.LONG_FORM_ON_DEMAND) | ((i3 >> 6) & 896), 104);
            }
            c0814p.p(false);
            c0814p.X(-132007852);
            if (z4) {
                H6.a(AbstractC3106b5.d(c0814p, R.string.assistant_settings_start_with_location), z3, function13, null, "answerWithLocationTag", null, 0L, c0814p, (i5 & ContentType.LONG_FORM_ON_DEMAND) | 24576 | ((i3 >> 9) & 896), 104);
            }
            c0814p.p(false);
            androidx.compose.animation.E.f((z || z2 || z3) ? false : true, null, null, null, null, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.b.a, c0814p, 1572870, 30);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.n(z, z2, z3, function1, function12, function13, str, str2, z4, qVar, i, 0);
        }
    }

    public static final void b(final com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m mVar, final LearnSettingsUpdateData learnSettingsUpdateData, final Function1 function1, final Function1 function12, final Function1 function13, final Function1 function14, final Function1 function15, final Function1 function16, final Function1 function17, final Function1 function18, final Function1 function19, final Function1 function110, final Function0 function0, final Function0 function02, final Function0 function03, final Function0 function04, final androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, final int i) {
        androidx.compose.ui.n nVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(114375660);
        int i2 = i | (c0814p.h(mVar) ? 4 : 2) | (c0814p.f(learnSettingsUpdateData) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.h(function12) ? 2048 : 1024) | (c0814p.h(function13) ? 16384 : 8192) | (c0814p.h(function14) ? 131072 : 65536) | (c0814p.h(function15) ? 1048576 : 524288) | (c0814p.h(function16) ? 8388608 : 4194304) | (c0814p.h(function17) ? 67108864 : 33554432) | (c0814p.h(function18) ? 536870912 : 268435456);
        int i3 = (c0814p.h(function19) ? 4 : 2) | (c0814p.h(function110) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128) | (c0814p.h(function02) ? 2048 : 1024) | (c0814p.h(function03) ? 16384 : 8192) | (c0814p.h(function04) ? 131072 : 65536) | (c0814p.f(qVar) ? 1048576 : 524288);
        if ((i2 & 306783379) == 306783378 && (i3 & 599187) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object[] objArr = {mVar.m};
            c0814p.X(267046712);
            boolean zH = c0814p.h(mVar);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.o(mVar, 1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 0, 6);
            androidx.compose.ui.q qVarU = AbstractC0460p.u(qVar.g(androidx.compose.foundation.layout.K0.c), AbstractC0460p.r(c0814p), false, 14);
            com.quizlet.themes.m mVar2 = com.quizlet.themes.m.g;
            mVar2.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarU2 = AbstractC0382e.u(qVarU, f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU2);
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
            d(learnSettingsUpdateData.a, learnSettingsUpdateData.b, learnSettingsUpdateData.c, function1, function12, function13, null, c0814p, (i2 << 3) & 523264);
            c0814p = c0814p;
            com.quizlet.qutils.string.g gVarF = AbstractC3274u5.f(mVar.n);
            androidx.compose.runtime.X0 x0 = AndroidCompositionLocals_androidKt.b;
            String strA = gVarF.a((Context) c0814p.j(x0));
            String strA2 = AbstractC3274u5.f(mVar.o).a((Context) c0814p.j(x0));
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            mVar2.p();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.j;
            a(learnSettingsUpdateData.d, learnSettingsUpdateData.e, learnSettingsUpdateData.f, function14, function15, function16, strA, strA2, mVar.p, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, (i2 >> 6) & 523264);
            mVar2.p();
            int i5 = i3 >> 12;
            int i6 = i2 >> 9;
            j(mVar.k, function04, learnSettingsUpdateData.g, learnSettingsUpdateData.h, learnSettingsUpdateData.i, function17, function18, function19, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, (i5 & ContentType.LONG_FORM_ON_DEMAND) | (458752 & i6) | (i6 & 3670016) | ((i3 << 21) & 29360128));
            if (mVar.r) {
                c0814p.X(-1351889517);
                mVar2.p();
                h(mVar.a, learnSettingsUpdateData.l, function110, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, (i3 << 3) & 896);
                c0814p = c0814p;
                c0814p.p(false);
                nVar = nVar2;
            } else {
                c0814p.X(-1351516556);
                GradingSettingsValues gradingSettingsValues = (GradingSettingsValues) interfaceC0773a0.getValue();
                Intrinsics.checkNotNullParameter(gradingSettingsValues, "<this>");
                String strD = AbstractC3106b5.d(c0814p, gradingSettingsValues.b ? R.string.assistant_settings_grading_options_smart_grading : R.string.assistant_settings_grading_options_standard_grading);
                mVar2.s();
                androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
                nVar = nVar2;
                e((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND, c0814p, qVarY, strD, function0);
                c0814p.p(false);
            }
            c0814p.X(-1844703565);
            if (mVar.q) {
                mVar2.p();
                l((i3 >> 9) & 14, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function02);
            }
            c0814p.p(false);
            mVar2.p();
            i(i5 & 14, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function03);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(learnSettingsUpdateData, function1, function12, function13, function14, function15, function16, function17, function18, function19, function110, function0, function02, function03, function04, qVar, i) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.k
                public final /* synthetic */ LearnSettingsUpdateData b;
                public final /* synthetic */ Function1 c;
                public final /* synthetic */ Function1 d;
                public final /* synthetic */ Function1 e;
                public final /* synthetic */ Function1 f;
                public final /* synthetic */ Function1 g;
                public final /* synthetic */ Function1 h;
                public final /* synthetic */ Function1 i;
                public final /* synthetic */ Function1 j;
                public final /* synthetic */ Function1 k;
                public final /* synthetic */ Function1 l;
                public final /* synthetic */ Function0 m;
                public final /* synthetic */ Function0 n;
                public final /* synthetic */ Function0 o;
                public final /* synthetic */ Function0 p;
                public final /* synthetic */ androidx.compose.ui.q q;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m mVar3 = this.a;
                    Function0 function05 = this.p;
                    androidx.compose.ui.q qVar2 = this.q;
                    D6.b(mVar3, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, this.n, this.o, function05, qVar2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void c(String str, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1158107964);
        int i2 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(str, qVar, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.a(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).k, c0814p, i2 & 126, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4214a(str, qVar, i, 9);
        }
    }

    public static final void d(final boolean z, final boolean z2, final boolean z3, final Function1 function1, final Function1 function12, final Function1 function13, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        boolean z4;
        boolean z5;
        final androidx.compose.ui.q qVar2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-47924340);
        if ((i & 6) == 0) {
            i2 = (c0814p2.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            z4 = z2;
            i2 |= c0814p2.g(z4) ? 32 : 16;
        } else {
            z4 = z2;
        }
        if ((i & 384) == 0) {
            z5 = z3;
            i2 |= c0814p2.g(z5) ? 256 : 128;
        } else {
            z5 = z3;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(function1) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(function12) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.h(function13) ? 131072 : 65536;
        }
        int i3 = i2 | 1572864;
        if ((599187 & i3) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            qVar2 = qVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, nVar);
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
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            G6.c(AbstractC3106b5.d(c0814p2, R.string.assistant_settings_group_general), null, c0814p2, 0);
            String strD = AbstractC3106b5.d(c0814p2, R.string.assistant_settings_group_general_shuffle);
            com.quizlet.themes.m.g.u();
            qVar2 = nVar;
            int i5 = i3 >> 3;
            H6.a(strD, z, function1, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "shuffleTag", null, 0L, c0814p2, ((i3 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 24576 | (i5 & 896), 96);
            c0814p = c0814p2;
            H6.a(AbstractC3106b5.d(c0814p, R.string.assistant_settings_group_general_audio), z4, function12, null, "audioTag", null, 0L, c0814p2, (i3 & ContentType.LONG_FORM_ON_DEMAND) | 24576 | ((i3 >> 6) & 896), 104);
            H6.a(AbstractC3106b5.d(c0814p, R.string.assistant_settings_group_general_retype_correct_answer), z5, function13, null, "retypeTag", null, 0L, c0814p2, (i5 & ContentType.LONG_FORM_ON_DEMAND) | 24576 | ((i3 >> 9) & 896), 104);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.l
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    Function1 function14 = function13;
                    androidx.compose.ui.q qVar3 = qVar2;
                    D6.d(z, z2, z3, function1, function12, function14, qVar3, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void e(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str, Function0 function0) {
        int i2;
        String str2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1232024806);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(str) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            str2 = str;
        } else {
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            androidx.compose.ui.q qVarL = AbstractC0460p.l(androidx.compose.foundation.layout.K0.f(qVar, com.quizlet.themes.m.q, DefinitionKt.NO_Float_VALUE, 2), false, null, function0, 7);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, hVar, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarL);
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
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, nVar);
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
            String strD = AbstractC3106b5.d(c0814p, R.string.assistant_settings_grading_options_title);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b(strD, null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).k, c0814p, 0, 0, 65534);
            androidx.compose.material3.Q4.b(str, null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).j, c0814p, i2 & 14, 0, 65530);
            str2 = str;
            c0814p = c0814p;
            c0814p.p(true);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            AbstractC0382e.f(c0814p, new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true));
            com.quizlet.themes.e.a(c0814p).a.getClass();
            AbstractC0460p.c(com.quizlet.ui.resources.icons.d.o(c0814p), null, null, null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 124);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.common.d(str2, function0, qVar, i);
        }
    }

    public static final void f(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1815646907);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.assistant_settings_personalization_explanation_set_page_simplification), null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).o, c0814p, 0, 0, 65534);
            c0814p = c0814p;
            String strD = AbstractC3106b5.d(c0814p, R.string.assistant_settings_personalization_explanation_set_page_simplification_button_turn_off);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.u();
            AbstractC3769y5.a(strD, androidx.compose.foundation.layout.K0.f(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), com.quizlet.themes.m.q, DefinitionKt.NO_Float_VALUE, 2), null, null, null, function0, c0814p, (i2 << 15) & 458752, 28);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.U(function0, qVar, i, 9);
        }
    }

    public static final void g(Function1 navigateBack, Function0 navigateToLearnSettingsGrading, androidx.compose.ui.q qVar, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        C0814p c0814p;
        int i2;
        com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar2;
        boolean z;
        androidx.compose.ui.q qVar3;
        com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar3;
        Intrinsics.checkNotNullParameter(navigateBack, "navigateBack");
        Intrinsics.checkNotNullParameter(navigateToLearnSettingsGrading, "navigateToLearnSettingsGrading");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1520563032);
        int i3 = i | (c0814p2.h(navigateToLearnSettingsGrading) ? 32 : 16) | 1408;
        if ((i3 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            qVar3 = qVar;
            aVar3 = aVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                qVar2 = androidx.compose.ui.n.b;
                c0814p2.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p2);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p2);
                c0814p2.Y(1729797275);
                c0814p = c0814p2;
                Object objE = AbstractC3417z1.e(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-7169);
                aVar2 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a) objE;
            } else {
                c0814p2.Q();
                i2 = i3 & (-7169);
                qVar2 = qVar;
                aVar2 = aVar;
                c0814p = c0814p2;
            }
            c0814p.q();
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i iVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) aVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(iVar.p, c0814p);
            kotlinx.coroutines.flow.d0 d0Var = iVar.q;
            c0814p.X(-1145517143);
            boolean z2 = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z2 || objI == v) {
                objI = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.r(null, navigateToLearnSettingsGrading, navigateBack);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            AbstractC0809m0 abstractC0809m0 = androidx.lifecycle.compose.g.a;
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zH = c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(b) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                objI2 = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.q(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
            c0814p.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar2, "learn_settings");
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
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
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.o oVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.o) interfaceC0773a0G.getValue();
            if (Intrinsics.b(oVar, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.n.a)) {
                c0814p.X(-1762795525);
                C0814p c0814p3 = c0814p;
                AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), c0814p3, 0, 1);
                c0814p = c0814p3;
                c0814p.p(false);
                z = true;
            } else {
                if (!(oVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-1762797240, c0814p, false);
                }
                c0814p.X(-1762790647);
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.o oVar2 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.o) interfaceC0773a0G.getValue();
                Intrinsics.e(oVar2, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUiState.Content");
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m mVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m) oVar2;
                c0814p.X(-1762788026);
                boolean zH2 = c0814p.h(aVar2);
                Object objI3 = c0814p.I();
                if (zH2 || objI3 == v) {
                    z = true;
                    com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y yVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y(1, aVar2, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a.class, "onEvent", "onEvent(Lcom/quizlet/quizletandroid/ui/studymodes/assistant/settings/data/LearnSettingsEvent;)V", 0, 3);
                    c0814p.i0(yVar);
                    objI3 = yVar;
                } else {
                    z = true;
                }
                c0814p.p(false);
                k(mVar, (Function1) ((kotlin.reflect.f) objI3), c0814p, 0, 0);
                c0814p.p(false);
            }
            c0814p.p(z);
            androidx.lifecycle.J j2 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            c0814p.X(-1145489945);
            boolean zH3 = c0814p.h(aVar2) | c0814p.h(j2);
            Object objI4 = c0814p.I();
            if (zH3 || objI4 == v) {
                objI4 = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.c(j2, aVar2, 1);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            C0776c.d(j2, (Function1) objI4, c0814p);
            qVar3 = qVar2;
            aVar3 = aVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.login.common.ui.a(navigateBack, navigateToLearnSettingsGrading, qVar3, aVar3, i, 3);
        }
    }

    public static final void h(kotlinx.collections.immutable.c cVar, WrittenQuestionGradingOption writtenQuestionGradingOption, Function1 function1, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1754877764);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(cVar) : c0814p.h(cVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(writtenQuestionGradingOption) : c0814p.h(writtenQuestionGradingOption) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(qVar) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            G6.c(AbstractC3106b5.d(c0814p, R.string.assistant_settings_grading_options_title_all_caps), null, c0814p, 0);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.q();
            com.quizlet.learn.settings.ui.b.a(cVar, writtenQuestionGradingOption, function1, AbstractC0382e.w(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, 1), c0814p, i2 & 1022);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.learn.settings.ui.a(cVar, writtenQuestionGradingOption, function1, qVar, i, 1);
        }
    }

    public static final void i(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1918519803);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            G6.c(AbstractC3106b5.d(c0814p, R.string.assistant_settings_group_misc), null, c0814p, 0);
            String strD = AbstractC3106b5.d(c0814p, R.string.assistant_settings_group_misc_restart);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.u();
            AbstractC3769y5.a(strD, androidx.compose.foundation.layout.K0.f(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), com.quizlet.themes.m.q, DefinitionKt.NO_Float_VALUE, 2), null, null, null, function0, c0814p, (i2 << 15) & 458752, 28);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.U(function0, qVar, i, 8);
        }
    }

    public static final void j(boolean z, Function0 function0, boolean z2, boolean z3, boolean z4, Function1 function1, Function1 function12, Function1 function13, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1870092095);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.g(z3) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.g(z4) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function1) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.h(function12) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.h(function13) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i2 |= c0814p.f(qVar) ? 67108864 : 33554432;
        }
        int i3 = i2;
        if ((i3 & 38347923) == 38347922 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            G6.c(AbstractC3106b5.d(c0814p, R.string.assistant_settings_group_question_types), null, c0814p, 0);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (z) {
                c0814p.X(-495675414);
                com.quizlet.themes.m.g.s();
                f((i3 >> 3) & 14, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function0);
                c0814p.p(false);
            } else {
                c0814p.X(-495438357);
                String strD = AbstractC3106b5.d(c0814p, R.string.assistant_settings_group_question_types_cards);
                com.quizlet.themes.m.g.u();
                int i5 = i3 >> 9;
                H6.a(strD, z2, function1, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "showFlashcardsTag", null, 0L, c0814p, ((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 24576 | (i5 & 896), 96);
                H6.a(AbstractC3106b5.d(c0814p, R.string.assistant_settings_group_question_types_mc), z3, function12, null, "showMultipleChoiceQuestionsTag", null, 0L, c0814p, ((i3 >> 6) & ContentType.LONG_FORM_ON_DEMAND) | 24576 | ((i3 >> 12) & 896), 104);
                H6.a(AbstractC3106b5.d(c0814p, R.string.assistant_settings_group_question_types_written), z4, function13, null, "showWrittenQuestionsTag", null, 0L, c0814p, (i5 & ContentType.LONG_FORM_ON_DEMAND) | 24576 | ((i3 >> 15) & 896), 104);
                androidx.compose.animation.E.f((z2 || z3 || z4) ? false : true, null, null, null, null, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.b.b, c0814p, 1572870, 30);
                c0814p = c0814p;
                c0814p.p(false);
            }
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.m(z, function0, z2, z3, z4, function1, function12, function13, qVar, i, 0);
        }
    }

    public static final void k(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m mVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i, int i2) {
        Function1 function12;
        int i3;
        Function1 function13;
        Function1 function14;
        int i4 = 6;
        int i5 = 0;
        int i6 = 2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-227479493);
        int i7 = i | (c0814p.h(mVar) ? 4 : 2);
        int i8 = i2 & 2;
        if (i8 != 0) {
            i3 = i7 | 48;
            function12 = function1;
        } else {
            function12 = function1;
            i3 = i7 | (c0814p.h(function12) ? 32 : 16);
        }
        int i9 = i3;
        if ((i9 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function14 = function12;
        } else {
            Object obj = C0804k.a;
            if (i8 != 0) {
                c0814p.X(1134336652);
                Object objI = c0814p.I();
                if (objI == obj) {
                    objI = new com.quizlet.quizletandroid.ui.login.z(13);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                function13 = (Function1) objI;
            } else {
                function13 = function12;
            }
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(true, mVar.l, c0814p, 6, 4);
            Object[] objArr = new Object[0];
            c0814p.X(1134344089);
            boolean zH = c0814p.h(mVar);
            Object objI2 = c0814p.I();
            if (zH || objI2 == obj) {
                objI2 = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.o(mVar, i5);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI2, c0814p, 0, 6);
            c0814p.X(1134373153);
            Object objI3 = c0814p.I();
            if (objI3 == obj) {
                objI3 = new com.quizlet.features.infra.folder.tag.composable.f(i4, interfaceC0773a0, function13);
                c0814p.i0(objI3);
            }
            Function0 function0 = (Function0) objI3;
            c0814p.p(false);
            androidx.work.impl.t.a(false, function0, c0814p, 48, 1);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-1603516673, new com.quizlet.quizletandroid.ui.startpage.nav2.composables.d(i6, function0), c0814p);
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            boolean z = true;
            AbstractC0725t3.a(null, dVarE, null, null, null, 0, 0L, 0L, c0374a, androidx.compose.runtime.internal.e.e(2100577098, new com.quizlet.assembly.compose.input.h(25, mVar, interfaceC0773a0, function13, false), c0814p), c0814p, 805306416, 253);
            c0814p.X(1134470486);
            boolean zH2 = c0814p.h(xVarH);
            int i10 = i9 & ContentType.LONG_FORM_ON_DEMAND;
            boolean zF = zH2 | (i10 == 32) | c0814p.f(interfaceC0773a0);
            Object objI4 = c0814p.I();
            if (zF || objI4 == obj) {
                objI4 = new com.quizlet.features.infra.basestudy.ui.g(xVarH, function13, interfaceC0773a0, 2);
                c0814p.i0(objI4);
            }
            Function0 function02 = (Function0) objI4;
            c0814p.p(false);
            c0814p.X(1134475798);
            if (i10 != 32) {
                z = false;
            }
            boolean zH3 = z | c0814p.h(xVarH);
            Object objI5 = c0814p.I();
            if (zH3 || objI5 == obj) {
                objI5 = new com.quizlet.features.folders.addtofolder.composables.j(function13, xVarH, 9);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            F6.c(xVarH, function02, (Function0) objI5, null, c0814p, 8);
            c0814p = c0814p;
            function14 = function13;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(mVar, function14, i, i2, 26);
        }
    }

    public static final void l(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(322199124);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            G6.c(AbstractC3106b5.d(c0814p, R.string.assistant_settings_personalization_enter_write), null, c0814p, 0);
            String strD = AbstractC3106b5.d(c0814p, R.string.write);
            androidx.compose.ui.graphics.painter.b bVarC = com.quizlet.themes.e.a(c0814p).b.c(c0814p);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.s();
            Y4.a(strD, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function0, false, false, null, null, 0L, 0L, null, bVarC, null, false, c0814p, (i2 << 6) & 896, 384, 3064);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.U(function0, qVar, i, 7);
        }
    }

    public static final NotesToValueInfo m(com.quizlet.shared.models.notes.c cVar, User user, boolean z) {
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        Intrinsics.checkNotNullParameter(user, "user");
        String strB = cVar.b();
        Boolean boolD = cVar.d();
        if (boolD != null) {
            z = !boolD.booleanValue();
        }
        boolean z2 = z;
        StudyNoteArtifactInfo$Title title = cVar.getTitle();
        com.quizlet.data.model.R1 r1N = title != null ? n(title) : null;
        TitleInfo titleInfo = r1N instanceof TitleInfo ? (TitleInfo) r1N : null;
        StudyNoteArtifactInfo$EssayPrompts studyNoteArtifactInfo$EssayPromptsC = cVar.c();
        com.quizlet.data.model.R1 r1N2 = studyNoteArtifactInfo$EssayPromptsC != null ? n(studyNoteArtifactInfo$EssayPromptsC) : null;
        EssayInfo essayInfo = r1N2 instanceof EssayInfo ? (EssayInfo) r1N2 : null;
        StudyNoteArtifactInfo$OutlineMarkdown studyNoteArtifactInfo$OutlineMarkdownA = cVar.a();
        com.quizlet.data.model.R1 r1N3 = studyNoteArtifactInfo$OutlineMarkdownA != null ? n(studyNoteArtifactInfo$OutlineMarkdownA) : null;
        OutlineMarkdownInfo outlineMarkdownInfo = r1N3 instanceof OutlineMarkdownInfo ? (OutlineMarkdownInfo) r1N3 : null;
        StudyNoteArtifactInfo$ReviewSheet studyNoteArtifactInfo$ReviewSheetE = cVar.e();
        com.quizlet.data.model.R1 r1N4 = studyNoteArtifactInfo$ReviewSheetE != null ? n(studyNoteArtifactInfo$ReviewSheetE) : null;
        ReviewSheetInfo reviewSheetInfo = r1N4 instanceof ReviewSheetInfo ? (ReviewSheetInfo) r1N4 : null;
        StudyNoteArtifactInfo$Flashcards studyNoteArtifactInfo$FlashcardsI = cVar.i();
        Object objN = studyNoteArtifactInfo$FlashcardsI != null ? n(studyNoteArtifactInfo$FlashcardsI) : null;
        FlashcardsInfo flashcardsInfo = objN instanceof FlashcardsInfo ? (FlashcardsInfo) objN : null;
        String strF = cVar.f();
        if (strF == null) {
            strF = "";
        }
        return new NotesToValueInfo(strB, z2, titleInfo, outlineMarkdownInfo, reviewSheetInfo, flashcardsInfo, essayInfo, user, strF, cVar.h(), cVar.g());
    }

    public static final com.quizlet.data.model.R1 n(com.quizlet.shared.models.notes.b bVar) {
        Intrinsics.checkNotNullParameter(bVar, "<this>");
        ArrayList arrayList = null;
        if (bVar instanceof StudyNoteArtifactInfo$EssayPrompts) {
            StudyNoteArtifactInfo$EssayPrompts studyNoteArtifactInfo$EssayPrompts = (StudyNoteArtifactInfo$EssayPrompts) bVar;
            String str = studyNoteArtifactInfo$EssayPrompts.c;
            String upperCase = studyNoteArtifactInfo$EssayPrompts.d.name().toUpperCase(Locale.ROOT);
            Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
            EnumC4175w enumC4175wValueOf = EnumC4175w.valueOf(upperCase);
            List<EssayPromptItem> list = studyNoteArtifactInfo$EssayPrompts.e;
            if (list != null) {
                arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                for (EssayPromptItem essayPromptItem : list) {
                    arrayList.add(new EssayItem(essayPromptItem.b, com.quizlet.data.model.T.valueOf(essayPromptItem.c.name())));
                }
            }
            return new EssayInfo(str, enumC4175wValueOf, arrayList);
        }
        if (bVar instanceof StudyNoteArtifactInfo$Flashcards) {
            StudyNoteArtifactInfo$Flashcards studyNoteArtifactInfo$Flashcards = (StudyNoteArtifactInfo$Flashcards) bVar;
            String str2 = studyNoteArtifactInfo$Flashcards.c;
            String upperCase2 = studyNoteArtifactInfo$Flashcards.d.name().toUpperCase(Locale.ROOT);
            Intrinsics.checkNotNullExpressionValue(upperCase2, "toUpperCase(...)");
            EnumC4175w enumC4175wValueOf2 = EnumC4175w.valueOf(upperCase2);
            Long l = studyNoteArtifactInfo$Flashcards.e;
            List<FlashcardItem> list2 = studyNoteArtifactInfo$Flashcards.f;
            if (list2 != null) {
                arrayList = new ArrayList(kotlin.collections.C.q(list2, 10));
                for (FlashcardItem flashcardItem : list2) {
                    arrayList.add(new FlashcardsTermDefinitionCard(flashcardItem.b, flashcardItem.c));
                }
            }
            return new FlashcardsInfo(str2, enumC4175wValueOf2, l, arrayList);
        }
        if (bVar instanceof StudyNoteArtifactInfo$OutlineMarkdown) {
            StudyNoteArtifactInfo$OutlineMarkdown studyNoteArtifactInfo$OutlineMarkdown = (StudyNoteArtifactInfo$OutlineMarkdown) bVar;
            String str3 = studyNoteArtifactInfo$OutlineMarkdown.c;
            String upperCase3 = studyNoteArtifactInfo$OutlineMarkdown.d.name().toUpperCase(Locale.ROOT);
            Intrinsics.checkNotNullExpressionValue(upperCase3, "toUpperCase(...)");
            return new OutlineMarkdownInfo(str3, EnumC4175w.valueOf(upperCase3), studyNoteArtifactInfo$OutlineMarkdown.e);
        }
        if (bVar instanceof StudyNoteArtifactInfo$Title) {
            StudyNoteArtifactInfo$Title studyNoteArtifactInfo$Title = (StudyNoteArtifactInfo$Title) bVar;
            String str4 = studyNoteArtifactInfo$Title.c;
            String upperCase4 = studyNoteArtifactInfo$Title.d.name().toUpperCase(Locale.ROOT);
            Intrinsics.checkNotNullExpressionValue(upperCase4, "toUpperCase(...)");
            return new TitleInfo(str4, EnumC4175w.valueOf(upperCase4), studyNoteArtifactInfo$Title.e);
        }
        if (!(bVar instanceof StudyNoteArtifactInfo$ReviewSheet)) {
            throw new NoWhenBranchMatchedException();
        }
        StudyNoteArtifactInfo$ReviewSheet studyNoteArtifactInfo$ReviewSheet = (StudyNoteArtifactInfo$ReviewSheet) bVar;
        String str5 = studyNoteArtifactInfo$ReviewSheet.c;
        String upperCase5 = studyNoteArtifactInfo$ReviewSheet.d.name().toUpperCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(upperCase5, "toUpperCase(...)");
        return new ReviewSheetInfo(str5, EnumC4175w.valueOf(upperCase5), studyNoteArtifactInfo$ReviewSheet.e);
    }
}
