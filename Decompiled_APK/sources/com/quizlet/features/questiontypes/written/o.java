package com.quizlet.features.questiontypes.written;

import androidx.compose.ui.node.B;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import assistantMode.enums.EnumC1452f;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3124d5;
import com.google.android.gms.internal.mlkit_vision_barcode.B6;
import com.google.android.gms.internal.mlkit_vision_camera.u3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3455g;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogData;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogger;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.z1;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.LocationQuestionSectionData;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.StudiableDiagramImage;
import com.quizlet.studiablemodels.StudiableText;
import com.quizlet.studiablemodels.WrittenStudiableQuestion;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer;
import com.quizlet.studiablemodels.grading.StudiableQuestionResponse;
import com.quizlet.studiablemodels.grading.WrittenResponse;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.UninitializedPropertyAccessException;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class o extends w0 implements a {
    public final androidx.work.impl.model.l b;
    public final com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a c;
    public final com.quizlet.quizletandroid.managers.audio.h d;
    public final QuestionEventLogger e;
    public final EventLogger f;
    public final com.quizlet.features.questiontypes.basequestion.c g;
    public final long h;
    public final WrittenStudiableQuestion i;
    public final A1 j;
    public final boolean k;
    public final QuestionSettings l;
    public final boolean m;
    public final String n;
    public com.quizlet.studiablemodels.grading.b o;
    public final s0 p;
    public final Z q;
    public final s0 r;
    public final Z s;
    public final s0 t;
    public final Z u;
    public final d0 v;
    public final Y w;
    public boolean x;
    public EnumC1452f y;

    public o(m0 savedStateHandle, androidx.work.impl.model.l smartGrader, com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a questionAnswerManager, com.quizlet.quizletandroid.managers.audio.h audioManager, QuestionEventLogger questionEventLogger, EventLogger eventLogger, com.quizlet.features.questiontypes.basequestion.c feedbackLabelUseCase) {
        Object value;
        com.quizlet.features.questiontypes.data.d dVar;
        DiagramData diagramDataA;
        com.quizlet.features.questiontypes.written.data.g gVar;
        Object[] args;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(smartGrader, "smartGrader");
        Intrinsics.checkNotNullParameter(questionAnswerManager, "questionAnswerManager");
        Intrinsics.checkNotNullParameter(audioManager, "audioManager");
        Intrinsics.checkNotNullParameter(questionEventLogger, "questionEventLogger");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(feedbackLabelUseCase, "feedbackLabelUseCase");
        this.b = smartGrader;
        this.c = questionAnswerManager;
        this.d = audioManager;
        this.e = questionEventLogger;
        this.f = eventLogger;
        this.g = feedbackLabelUseCase;
        Object objA = savedStateHandle.a("ARG_SET_ID");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.h = ((Number) objA).longValue();
        Object objA2 = savedStateHandle.a("ARG_STUDIABLE_QUESTION");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        WrittenStudiableQuestion writtenStudiableQuestion = (WrittenStudiableQuestion) objA2;
        this.i = writtenStudiableQuestion;
        z1 z1Var = A1.Companion;
        Object objA3 = savedStateHandle.a("ARG_STUDY_MODE_TYPE");
        if (objA3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        int iIntValue = ((Number) objA3).intValue();
        z1Var.getClass();
        this.j = z1.a(iIntValue);
        Object objA4 = savedStateHandle.a("ARG_SHOW_FEEDBACK");
        if (objA4 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.k = ((Boolean) objA4).booleanValue();
        Object objA5 = savedStateHandle.a("ARG_SETTINGS");
        if (objA5 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.l = (QuestionSettings) objA5;
        Object objA6 = savedStateHandle.a("ARG_DID_MISS_QUESTION");
        if (objA6 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.m = ((Boolean) objA6).booleanValue();
        String questionSessionId = B.f("toString(...)");
        this.n = questionSessionId;
        s0 s0VarC = e0.c(p.a);
        this.p = s0VarC;
        this.q = new Z(s0VarC);
        s0 s0VarC2 = e0.c(Boolean.FALSE);
        this.r = s0VarC2;
        this.s = new Z(s0VarC2);
        s0 s0VarC3 = e0.c(null);
        this.t = s0VarC3;
        this.u = new Z(s0VarC3);
        d0 d0VarB = e0.b(0, 0, null, 7);
        this.v = d0VarB;
        this.w = new Y(d0VarB);
        this.y = EnumC1452f.d;
        Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
        com.quizlet.features.questiontypes.grading.a aVar = (com.quizlet.features.questiontypes.grading.a) smartGrader.b;
        Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
        aVar.b = questionSessionId;
        QuestionSectionData questionSectionData = writtenStudiableQuestion.b;
        DefaultQuestionSectionData defaultQuestionSectionData = questionSectionData instanceof DefaultQuestionSectionData ? (DefaultQuestionSectionData) questionSectionData : null;
        do {
            value = s0VarC.getValue();
            if (defaultQuestionSectionData != null) {
                StudiableText studiableText = defaultQuestionSectionData.a;
                dVar = new com.quizlet.features.questiontypes.data.d(studiableText != null ? B6.f(studiableText, false) : null, defaultQuestionSectionData.b);
            } else {
                dVar = null;
            }
            WrittenStudiableQuestion writtenStudiableQuestion2 = this.i;
            QuestionSectionData questionSectionData2 = writtenStudiableQuestion2.b;
            LocationQuestionSectionData locationQuestionSectionData = questionSectionData2 instanceof LocationQuestionSectionData ? (LocationQuestionSectionData) questionSectionData2 : null;
            StudiableDiagramImage studiableDiagramImage = writtenStudiableQuestion2.c.e;
            if (studiableDiagramImage == null || locationQuestionSectionData == null) {
                diagramDataA = null;
            } else {
                DiagramData.Builder builder = new DiagramData.Builder();
                builder.c(AbstractC3124d5.c(studiableDiagramImage));
                builder.b(A.b(AbstractC3124d5.b(locationQuestionSectionData)));
                diagramDataA = builder.a();
            }
            gVar = new com.quizlet.features.questiontypes.written.data.g(dVar, diagramDataA != null ? new com.quizlet.features.questiontypes.data.b(diagramDataA) : null);
            args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
        } while (!s0VarC.k(value, new q(gVar, new com.quizlet.features.questiontypes.written.data.f(new com.quizlet.features.questiontypes.written.ui.i(new com.quizlet.qutils.string.f(R.string.written_placeholder, C4933y.P(args)), 1021), null), com.quizlet.features.questiontypes.basequestion.data.a.a, this.m, null, null)));
        if (this.l.c) {
            G();
        }
    }

    public static final Unit A(o oVar, boolean z) {
        if (!(((r) oVar.p.getValue()) instanceof q)) {
            return Unit.a;
        }
        Boolean boolValueOf = Boolean.valueOf(z);
        s0 s0Var = oVar.r;
        s0Var.getClass();
        s0Var.m(null, boolValueOf);
        Unit unit = Unit.a;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        return unit;
    }

    public static void D(o oVar, String str, Integer num, String str2, String str3, A1 a1, int i) {
        assistantMode.enums.k kVar = assistantMode.enums.k.b;
        Integer num2 = (i & 2) != 0 ? null : num;
        String str4 = (i & 4) != 0 ? null : str2;
        String str5 = (i & 8) != 0 ? null : str3;
        A1 a12 = (i & 16) != 0 ? null : a1;
        assistantMode.enums.k kVar2 = (i & 32) != 0 ? null : kVar;
        oVar.getClass();
        QuestionEventLogData.a.getClass();
        QuestionEventLogger.DefaultImpls.a(oVar.e, oVar.n, str, QuestionEventLogData.Companion.a(oVar.i), 1, num2, str4, null, str5, a12, kVar2, 256);
    }

    public final void B(com.quizlet.features.questiontypes.written.data.a aVar, String str) {
        try {
            E.A(p0.j(this), null, null, new j(this, aVar, str, null), 3);
        } catch (UninitializedPropertyAccessException e) {
            timber.log.c.a.p(e);
        }
    }

    public final void C(com.quizlet.features.questiontypes.written.data.a aVar, String str, com.quizlet.studiablemodels.grading.b bVar) {
        EnumC1452f enumC1452f;
        int iOrdinal = aVar.ordinal();
        if (iOrdinal == 0) {
            enumC1452f = (this.x || !bVar.a.a) ? EnumC1452f.b : EnumC1452f.c;
        } else if (iOrdinal == 1 || iOrdinal == 2) {
            enumC1452f = EnumC1452f.b;
        } else if (iOrdinal != 3) {
            if (iOrdinal != 4) {
                throw new NoWhenBranchMatchedException();
            }
            enumC1452f = EnumC1452f.b;
        } else {
            enumC1452f = EnumC1452f.c;
        }
        this.y = enumC1452f;
        int iOrdinal2 = aVar.ordinal();
        if (iOrdinal2 == 0) {
            StudiableQuestionResponse studiableQuestionResponse = bVar.a.b.a;
            Intrinsics.e(studiableQuestionResponse, "null cannot be cast to non-null type com.quizlet.studiablemodels.grading.WrittenResponse");
            Integer numValueOf = Integer.valueOf(this.y.a);
            String str2 = ((WrittenResponse) studiableQuestionResponse).a;
            D(this, "answer", numValueOf, str2, null, null, 56);
            D(this, "view_correct_answer", Integer.valueOf(this.y.a), str2, null, null, 56);
            H(bVar, str, false);
            return;
        }
        EventLogger eventLogger = this.f;
        if (iOrdinal2 == 1) {
            eventLogger.q("question_written_answer_reveal");
            H(bVar, str, true);
            return;
        }
        if (iOrdinal2 == 2) {
            eventLogger.q("question_skip");
            E();
        } else if (iOrdinal2 == 3) {
            D(this, "override", null, null, null, null, 62);
            eventLogger.q("question_i_mistyped");
            I(bVar, true);
        } else {
            if (iOrdinal2 != 4) {
                throw new NoWhenBranchMatchedException();
            }
            D(this, "override_to_incorrect", null, null, null, null, 62);
            eventLogger.q("question_i_mistyped_i_was_incorrect");
            I(bVar, false);
        }
    }

    public final void E() {
        E.A(p0.j(this), null, null, new k(this, null), 3);
    }

    public final void F(u3 event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (event instanceof b) {
            B(com.quizlet.features.questiontypes.written.data.a.a, ((b) event).a);
            return;
        }
        if (event instanceof e) {
            e eVar = (e) event;
            com.quizlet.features.questiontypes.written.data.a aVar = eVar.c;
            if (aVar != null) {
                B(aVar, eVar.a);
                return;
            }
            return;
        }
        if (event instanceof d) {
            G();
        } else {
            if (!(event instanceof c)) {
                throw new NoWhenBranchMatchedException();
            }
            E.A(p0.j(this), null, null, new i(this, this.l.c ? 600L : 1200L, null), 3);
        }
    }

    public final void G() {
        if (this.i.c.a()) {
            return;
        }
        E.A(p0.j(this), new androidx.compose.ui.text.font.o(C5041z.a, 5), null, new l(this, null), 2);
    }

    public final void H(com.quizlet.studiablemodels.grading.b bVar, String str, boolean z) {
        AbstractC3455g eVar;
        AbstractC3455g cVar;
        StudiableQuestionGradedAnswer studiableQuestionGradedAnswer = bVar.a;
        StudiableQuestionResponse studiableQuestionResponse = studiableQuestionGradedAnswer.b.b;
        Intrinsics.e(studiableQuestionResponse, "null cannot be cast to non-null type com.quizlet.studiablemodels.grading.WrittenResponse");
        String str2 = ((WrittenResponse) studiableQuestionResponse).a;
        if (z) {
            cVar = new com.quizlet.features.questiontypes.written.data.d(B6.g(str2));
        } else {
            boolean z2 = studiableQuestionGradedAnswer.a;
            if (z2 && studiableQuestionGradedAnswer.f.a) {
                eVar = new com.quizlet.features.questiontypes.written.data.b(B6.g(str), B6.g(str2));
            } else {
                com.quizlet.features.questiontypes.basequestion.c cVar2 = this.g;
                if (z2) {
                    com.quizlet.features.infra.models.a aVarG = B6.g(str);
                    cVar2.getClass();
                    cVar = new com.quizlet.features.questiontypes.written.data.c(aVarG, com.quizlet.features.questiontypes.basequestion.c.a(this.m));
                } else {
                    com.quizlet.features.infra.models.a aVarG2 = B6.g(str);
                    com.quizlet.features.infra.models.a aVarG3 = B6.g(str2);
                    cVar2.getClass();
                    eVar = new com.quizlet.features.questiontypes.written.data.e(aVarG2, aVarG3, com.quizlet.features.questiontypes.basequestion.c.b());
                }
            }
            cVar = eVar;
        }
        E.A(p0.j(this), null, null, new n(this, cVar, studiableQuestionGradedAnswer, (!this.k || (cVar instanceof com.quizlet.features.questiontypes.written.data.c)) ? com.quizlet.features.questiontypes.basequestion.data.a.c : com.quizlet.features.questiontypes.basequestion.data.a.b, z, null), 3);
    }

    public final void I(com.quizlet.studiablemodels.grading.b bVar, boolean z) {
        s0 s0Var;
        Object value;
        r rVar;
        StudiableQuestionResponse studiableQuestionResponse = bVar.a.b.a;
        Intrinsics.e(studiableQuestionResponse, "null cannot be cast to non-null type com.quizlet.studiablemodels.grading.WrittenResponse");
        WrittenResponse writtenResponse = (WrittenResponse) studiableQuestionResponse;
        StudiableQuestionResponse studiableQuestionResponse2 = bVar.a.b.b;
        Intrinsics.e(studiableQuestionResponse2, "null cannot be cast to non-null type com.quizlet.studiablemodels.grading.WrittenResponse");
        WrittenResponse writtenResponse2 = (WrittenResponse) studiableQuestionResponse2;
        if (z) {
            E.A(p0.j(this), null, null, new i(this, 0L, null), 3);
            return;
        }
        com.quizlet.features.infra.models.a aVarG = B6.g(writtenResponse.a);
        com.quizlet.features.infra.models.a aVarG2 = B6.g(writtenResponse2.a);
        this.g.getClass();
        com.quizlet.features.questiontypes.written.data.e eVar = new com.quizlet.features.questiontypes.written.data.e(aVarG, aVarG2, com.quizlet.features.questiontypes.basequestion.c.b());
        do {
            s0Var = this.p;
            value = s0Var.getValue();
            rVar = (r) value;
            Intrinsics.e(rVar, "null cannot be cast to non-null type com.quizlet.features.questiontypes.written.WrittenUiState.ViewState");
        } while (!s0Var.k(value, q.a((q) rVar, eVar, com.quizlet.features.questiontypes.basequestion.data.a.b, new com.quizlet.features.questiontypes.composables.d(R.string.continue_button, new com.quizlet.features.notes.paywall.a(0, this, o.class, "onContinueClick", "onContinueClick$questiontypes_release()V", 0, 20)), null)));
    }
}
