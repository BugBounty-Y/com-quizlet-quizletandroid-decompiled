package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.LayoutWeightElement;
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
import assistantMode.enums.EnumC1448b;
import assistantMode.grading.LocalGradedAnswerMetadata;
import assistantMode.grading.MatchingGameAnswerPair;
import assistantMode.grading.SmartGradedAnswerMetadata;
import assistantMode.types.AssistantGradingSettingsSuggestion;
import assistantMode.types.BooleanAnswer;
import assistantMode.types.Feedback;
import assistantMode.types.GradedAnswer;
import assistantMode.types.MatchingAnswer;
import assistantMode.types.MatchingGameAnswer;
import assistantMode.types.MultiPartAnswer;
import assistantMode.types.OptionIndexAnswer;
import assistantMode.types.OptionIndicesAnswer;
import assistantMode.types.QuestionElement;
import assistantMode.types.RevealSelfAssessmentAnswer;
import assistantMode.types.StringAnswer;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.features.flashcards.C4242p;
import com.quizlet.generated.enums.EnumC4508o1;
import com.quizlet.quizletandroid.R;
import com.quizlet.shared.models.api.grading.LongtextGradingResult;
import com.quizlet.studiablemodels.grading.FillInTheBlankResponse;
import com.quizlet.studiablemodels.grading.MatchingGameResponse;
import com.quizlet.studiablemodels.grading.MultipleChoiceResponse;
import com.quizlet.studiablemodels.grading.PGradedAnswerMetadata;
import com.quizlet.studiablemodels.grading.PLocalGradedAnswerMetadata;
import com.quizlet.studiablemodels.grading.PLongtextGradingResult;
import com.quizlet.studiablemodels.grading.PSmartGradedAnswerMetadata;
import com.quizlet.studiablemodels.grading.RevealSelfAssessmentResponse;
import com.quizlet.studiablemodels.grading.StudiableQuestionFeedback;
import com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer;
import com.quizlet.studiablemodels.grading.StudiableQuestionResponse;
import com.quizlet.studiablemodels.grading.TrueFalseResponse;
import com.quizlet.studiablemodels.grading.WrittenResponse;
import com.quizlet.ui.compose.EnumC4819l;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.f5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3142f5 {
    public static final void a(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-317264523);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.screens.b(i, 1, function0);
        }
    }

    public static final void b(com.quizlet.data.model.v2 userProfileAvatarData, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function0 function03, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(userProfileAvatarData, "userProfileAvatarData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1986810723);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(userProfileAvatarData) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function0) ? 256 : 128;
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
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(qVar, 1.0f), "home_top_bar");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(nVar, ((com.quizlet.themes.b) c0814p.j(b)).b.g(), androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(AbstractC0382e.u(qVarF, f), DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.M0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            mVar.s();
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g(f), androidx.compose.ui.b.k, c0814p, 48);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarY);
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
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            AbstractC3314z5.c(AbstractC3106b5.d(c0814p, R.string.search), new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true), function0, ((com.quizlet.themes.b) c0814p.j(b)).M0, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), com.quizlet.themes.m.N0, c0814p, i2 & 896);
            c0814p = c0814p;
            a(function03, c0814p, (i2 >> 12) & 14);
            AbstractC3169i5.a(userProfileAvatarData, null, function02, c0814p, ((i2 >> 3) & 896) | (i2 & 14));
            c0814p.p(true);
            long jG = ((com.quizlet.themes.b) c0814p.j(b)).b.g();
            EnumC4819l enumC4819l = EnumC4819l.a;
            mVar.q();
            AbstractC3241q5.a(androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.K0.f(nVar, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, 2), 1.0f), "linear_gradient"), jG, 0L, enumC4819l, c0814p, 3072, 4);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(userProfileAvatarData, qVar, function0, function02, function03, i, 4);
        }
    }

    public static final void c(com.quizlet.features.home.viewmodel.e viewModel, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-795954077);
        int i2 = i | (c0814p2.f(viewModel) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.h(function0) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            com.quizlet.data.model.v2 v2Var = (com.quizlet.data.model.v2) AbstractC3409x1.g(((com.quizlet.quizletandroid.ui.startpage.nav2.Y) viewModel).z1, c0814p2).getValue();
            c0814p2.X(-443631750);
            int i3 = i2 & 14;
            boolean z2 = i3 == 4;
            Object objI = c0814p2.I();
            if (z2 || objI == v) {
                z = false;
                C4242p c4242p = new C4242p(0, viewModel, com.quizlet.features.home.viewmodel.e.class, "onSearchBarClick", "onSearchBarClick()V", 0, 18);
                c0814p2.i0(c4242p);
                objI = c4242p;
            } else {
                z = false;
            }
            c0814p2.p(z);
            Function0 function02 = (Function0) ((kotlin.reflect.f) objI);
            c0814p2.X(-443629666);
            boolean z3 = i3 != 4 ? z : true;
            Object objI2 = c0814p2.I();
            if (z3 || objI2 == v) {
                C4242p c4242p2 = new C4242p(0, viewModel, com.quizlet.features.home.viewmodel.e.class, "onProfileAvatarClick", "onProfileAvatarClick()V", 0, 19);
                c0814p2.i0(c4242p2);
                objI2 = c4242p2;
            }
            c0814p2.p(z);
            c0814p = c0814p2;
            b(v2Var, qVar, function02, (Function0) ((kotlin.reflect.f) objI2), function0, c0814p, (i2 & ContentType.LONG_FORM_ON_DEMAND) | ((i2 << 6) & 57344));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 23, viewModel, qVar, function0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x0063 A[LOOP:0: B:4:0x000d->B:35:0x0063, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0066 A[EDGE_INSN: B:40:0x0066->B:36:0x0066 BREAK  A[LOOP:0: B:4:0x000d->B:35:0x0063], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.semantics.o d(androidx.compose.ui.node.E r8, boolean r9) {
        /*
            androidx.compose.ui.node.V r0 = r8.w
            java.lang.Object r0 = r0.f
            androidx.compose.ui.p r0 = (androidx.compose.ui.p) r0
            int r1 = r0.d
            r1 = r1 & 8
            r2 = 0
            if (r1 == 0) goto L66
        Ld:
            if (r0 == 0) goto L66
            int r1 = r0.c
            r1 = r1 & 8
            if (r1 == 0) goto L5d
            r1 = r0
            r3 = r2
        L17:
            if (r1 == 0) goto L5d
            boolean r4 = r1 instanceof androidx.compose.ui.node.n0
            if (r4 == 0) goto L1f
            r2 = r1
            goto L66
        L1f:
            int r4 = r1.c
            r4 = r4 & 8
            if (r4 == 0) goto L58
            boolean r4 = r1 instanceof androidx.compose.ui.node.AbstractC0918n
            if (r4 == 0) goto L58
            r4 = r1
            androidx.compose.ui.node.n r4 = (androidx.compose.ui.node.AbstractC0918n) r4
            androidx.compose.ui.p r4 = r4.o
            r5 = 0
        L2f:
            r6 = 1
            if (r4 == 0) goto L55
            int r7 = r4.c
            r7 = r7 & 8
            if (r7 == 0) goto L52
            int r5 = r5 + 1
            if (r5 != r6) goto L3e
            r1 = r4
            goto L52
        L3e:
            if (r3 != 0) goto L49
            androidx.compose.runtime.collection.b r3 = new androidx.compose.runtime.collection.b
            r6 = 16
            androidx.compose.ui.p[] r6 = new androidx.compose.ui.p[r6]
            r3.<init>(r6)
        L49:
            if (r1 == 0) goto L4f
            r3.b(r1)
            r1 = r2
        L4f:
            r3.b(r4)
        L52:
            androidx.compose.ui.p r4 = r4.f
            goto L2f
        L55:
            if (r5 != r6) goto L58
            goto L17
        L58:
            androidx.compose.ui.p r1 = androidx.compose.ui.node.AbstractC0910f.f(r3)
            goto L17
        L5d:
            int r1 = r0.d
            r1 = r1 & 8
            if (r1 == 0) goto L66
            androidx.compose.ui.p r0 = r0.f
            goto Ld
        L66:
            kotlin.jvm.internal.Intrinsics.d(r2)
            androidx.compose.ui.node.n0 r2 = (androidx.compose.ui.node.n0) r2
            androidx.compose.ui.p r2 = (androidx.compose.ui.p) r2
            androidx.compose.ui.p r0 = r2.a
            androidx.compose.ui.semantics.k r1 = r8.o()
            kotlin.jvm.internal.Intrinsics.d(r1)
            androidx.compose.ui.semantics.o r2 = new androidx.compose.ui.semantics.o
            r2.<init>(r0, r9, r8, r1)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5.d(androidx.compose.ui.node.E, boolean):androidx.compose.ui.semantics.o");
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x006c A[LOOP:0: B:4:0x000d->B:37:0x006c, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:42:0x006f A[EDGE_INSN: B:42:0x006f->B:38:0x006f BREAK  A[LOOP:0: B:4:0x000d->B:37:0x006c], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.node.n0 e(androidx.compose.ui.node.E r7) {
        /*
            androidx.compose.ui.node.V r7 = r7.w
            java.lang.Object r7 = r7.f
            androidx.compose.ui.p r7 = (androidx.compose.ui.p) r7
            int r0 = r7.d
            r0 = r0 & 8
            r1 = 0
            if (r0 == 0) goto L6f
        Ld:
            if (r7 == 0) goto L6f
            int r0 = r7.c
            r0 = r0 & 8
            if (r0 == 0) goto L66
            r0 = r7
            r2 = r1
        L17:
            if (r0 == 0) goto L66
            boolean r3 = r0 instanceof androidx.compose.ui.node.n0
            if (r3 == 0) goto L28
            r3 = r0
            androidx.compose.ui.node.n0 r3 = (androidx.compose.ui.node.n0) r3
            boolean r3 = r3.x0()
            if (r3 == 0) goto L61
            r1 = r0
            goto L6f
        L28:
            int r3 = r0.c
            r3 = r3 & 8
            if (r3 == 0) goto L61
            boolean r3 = r0 instanceof androidx.compose.ui.node.AbstractC0918n
            if (r3 == 0) goto L61
            r3 = r0
            androidx.compose.ui.node.n r3 = (androidx.compose.ui.node.AbstractC0918n) r3
            androidx.compose.ui.p r3 = r3.o
            r4 = 0
        L38:
            r5 = 1
            if (r3 == 0) goto L5e
            int r6 = r3.c
            r6 = r6 & 8
            if (r6 == 0) goto L5b
            int r4 = r4 + 1
            if (r4 != r5) goto L47
            r0 = r3
            goto L5b
        L47:
            if (r2 != 0) goto L52
            androidx.compose.runtime.collection.b r2 = new androidx.compose.runtime.collection.b
            r5 = 16
            androidx.compose.ui.p[] r5 = new androidx.compose.ui.p[r5]
            r2.<init>(r5)
        L52:
            if (r0 == 0) goto L58
            r2.b(r0)
            r0 = r1
        L58:
            r2.b(r3)
        L5b:
            androidx.compose.ui.p r3 = r3.f
            goto L38
        L5e:
            if (r4 != r5) goto L61
            goto L17
        L61:
            androidx.compose.ui.p r0 = androidx.compose.ui.node.AbstractC0910f.f(r2)
            goto L17
        L66:
            int r0 = r7.d
            r0 = r0 & 8
            if (r0 == 0) goto L6f
            androidx.compose.ui.p r7 = r7.f
            goto Ld
        L6f:
            androidx.compose.ui.node.n0 r1 = (androidx.compose.ui.node.n0) r1
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5.e(androidx.compose.ui.node.E):androidx.compose.ui.node.n0");
    }

    public static final assistantMode.types.v f(StudiableQuestionResponse studiableQuestionResponse) {
        EnumC1448b value;
        Intrinsics.checkNotNullParameter(studiableQuestionResponse, "<this>");
        if (studiableQuestionResponse instanceof WrittenResponse) {
            assistantMode.types.u uVar = assistantMode.types.v.Companion;
            String value2 = ((WrittenResponse) studiableQuestionResponse).a;
            uVar.getClass();
            Intrinsics.checkNotNullParameter(value2, "value");
            return new StringAnswer(value2);
        }
        if (studiableQuestionResponse instanceof TrueFalseResponse) {
            assistantMode.types.u uVar2 = assistantMode.types.v.Companion;
            boolean z = ((TrueFalseResponse) studiableQuestionResponse).a;
            uVar2.getClass();
            return new BooleanAnswer(z);
        }
        if (studiableQuestionResponse instanceof MultipleChoiceResponse) {
            assistantMode.types.u uVar3 = assistantMode.types.v.Companion;
            int i = ((MultipleChoiceResponse) studiableQuestionResponse).a;
            uVar3.getClass();
            return new OptionIndexAnswer(i);
        }
        if (studiableQuestionResponse instanceof RevealSelfAssessmentResponse) {
            assistantMode.types.u uVar4 = assistantMode.types.v.Companion;
            int iOrdinal = ((RevealSelfAssessmentResponse) studiableQuestionResponse).a.ordinal();
            if (iOrdinal == 0) {
                value = EnumC1448b.c;
            } else {
                if (iOrdinal != 1) {
                    throw new NoWhenBranchMatchedException();
                }
                value = EnumC1448b.d;
            }
            uVar4.getClass();
            Intrinsics.checkNotNullParameter(value, "value");
            return new RevealSelfAssessmentAnswer(value);
        }
        if (studiableQuestionResponse instanceof MatchingGameResponse) {
            assistantMode.types.u uVar5 = assistantMode.types.v.Companion;
            MatchingGameResponse matchingGameResponse = (MatchingGameResponse) studiableQuestionResponse;
            MatchingGameAnswerPair value3 = new MatchingGameAnswerPair(matchingGameResponse.a, matchingGameResponse.b);
            uVar5.getClass();
            Intrinsics.checkNotNullParameter(value3, "value");
            return new MatchingGameAnswer(value3);
        }
        if (!(studiableQuestionResponse instanceof FillInTheBlankResponse)) {
            throw new NoWhenBranchMatchedException();
        }
        assistantMode.types.u uVar6 = assistantMode.types.v.Companion;
        String value4 = (String) CollectionsKt.firstOrNull(((FillInTheBlankResponse) studiableQuestionResponse).a);
        if (value4 == null) {
            value4 = "";
        }
        uVar6.getClass();
        Intrinsics.checkNotNullParameter(value4, "value");
        return new StringAnswer(value4);
    }

    public static final StudiableQuestionGradedAnswer g(GradedAnswer gradedAnswer, List shapes) {
        LinkedHashMap linkedHashMap;
        PLongtextGradingResult pLongtextGradingResult;
        PGradedAnswerMetadata pSmartGradedAnswerMetadata;
        EnumC4508o1 enumC4508o1;
        Intrinsics.checkNotNullParameter(gradedAnswer, "<this>");
        Intrinsics.checkNotNullParameter(shapes, "shapes");
        boolean z = gradedAnswer.a;
        Feedback feedback = gradedAnswer.b;
        QuestionElement questionElement = feedback.c;
        if (questionElement == null) {
            throw new IllegalArgumentException("Expected answer is required for questions from NSidedCards.");
        }
        Map map = feedback.d;
        if (map != null) {
            linkedHashMap = new LinkedHashMap(kotlin.collections.U.a(map.size()));
            for (Map.Entry entry : map.entrySet()) {
                linkedHashMap.put(entry.getKey(), com.quizlet.studiablemodels.grading.c.c((QuestionElement) entry.getValue(), shapes));
            }
        } else {
            linkedHashMap = null;
        }
        assistantMode.types.v vVar = feedback.a;
        StudiableQuestionFeedback studiableQuestionFeedback = new StudiableQuestionFeedback(vVar != null ? h(vVar) : null, h(feedback.b), com.quizlet.studiablemodels.grading.c.c(questionElement, shapes), linkedHashMap);
        AssistantGradingSettingsSuggestion assistantGradingSettingsSuggestion = gradedAnswer.c;
        Boolean bool = assistantGradingSettingsSuggestion != null ? assistantGradingSettingsSuggestion.a : null;
        Boolean bool2 = assistantGradingSettingsSuggestion != null ? assistantGradingSettingsSuggestion.b : null;
        assistantMode.grading.b bVar = gradedAnswer.d;
        Intrinsics.checkNotNullParameter(bVar, "<this>");
        if (bVar instanceof LocalGradedAnswerMetadata) {
            pSmartGradedAnswerMetadata = PLocalGradedAnswerMetadata.b;
        } else {
            if (!(bVar instanceof SmartGradedAnswerMetadata)) {
                throw new NoWhenBranchMatchedException();
            }
            SmartGradedAnswerMetadata smartGradedAnswerMetadata = (SmartGradedAnswerMetadata) bVar;
            LongtextGradingResult longtextGradingResult = smartGradedAnswerMetadata.a;
            if (longtextGradingResult != null) {
                com.quizlet.shared.enums.l lVar = longtextGradingResult.a;
                Intrinsics.checkNotNullParameter(lVar, "<this>");
                int iOrdinal = lVar.ordinal();
                if (iOrdinal == 0) {
                    enumC4508o1 = EnumC4508o1.CORRECT;
                } else if (iOrdinal == 1) {
                    enumC4508o1 = EnumC4508o1.CLOSE;
                } else if (iOrdinal == 2) {
                    enumC4508o1 = EnumC4508o1.PARTIAL;
                } else {
                    if (iOrdinal != 3) {
                        throw new NoWhenBranchMatchedException();
                    }
                    enumC4508o1 = EnumC4508o1.WRONG;
                }
                pLongtextGradingResult = new PLongtextGradingResult(enumC4508o1, longtextGradingResult.b, longtextGradingResult.c, longtextGradingResult.d, longtextGradingResult.e);
            } else {
                pLongtextGradingResult = null;
            }
            pSmartGradedAnswerMetadata = new PSmartGradedAnswerMetadata(pLongtextGradingResult, smartGradedAnswerMetadata.b, smartGradedAnswerMetadata.c, smartGradedAnswerMetadata.d, smartGradedAnswerMetadata.e);
        }
        return new StudiableQuestionGradedAnswer(z, studiableQuestionFeedback, bool, bool2, false, pSmartGradedAnswerMetadata);
    }

    public static final StudiableQuestionResponse h(assistantMode.types.v vVar) {
        com.quizlet.studiablemodels.grading.a aVar;
        if (vVar instanceof StringAnswer) {
            return new WrittenResponse(((StringAnswer) vVar).a);
        }
        if (vVar instanceof BooleanAnswer) {
            return new TrueFalseResponse(((BooleanAnswer) vVar).a);
        }
        if (vVar instanceof OptionIndexAnswer) {
            return new MultipleChoiceResponse((int) ((OptionIndexAnswer) vVar).a);
        }
        if (vVar instanceof RevealSelfAssessmentAnswer) {
            int iOrdinal = ((RevealSelfAssessmentAnswer) vVar).a.ordinal();
            if (iOrdinal == 3) {
                aVar = com.quizlet.studiablemodels.grading.a.a;
            } else {
                if (iOrdinal != 4) {
                    throw new RuntimeException("Not a valid RevealSelfAssessmentOption: [" + EnumC1448b.class + "]");
                }
                aVar = com.quizlet.studiablemodels.grading.a.b;
            }
            return new RevealSelfAssessmentResponse(aVar);
        }
        if (vVar instanceof MatchingGameAnswer) {
            MatchingGameAnswerPair matchingGameAnswerPair = ((MatchingGameAnswer) vVar).a;
            return new MatchingGameResponse(matchingGameAnswerPair.a, matchingGameAnswerPair.b);
        }
        if (!(vVar instanceof MatchingAnswer) && !(vVar instanceof OptionIndicesAnswer) && !(vVar instanceof MultiPartAnswer)) {
            throw new NoWhenBranchMatchedException();
        }
        throw new RuntimeException("Not a supported ResponseType: [" + vVar.getClass() + "]");
    }
}
