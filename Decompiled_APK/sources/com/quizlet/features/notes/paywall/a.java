package com.quizlet.features.notes.paywall;

import android.app.Activity;
import android.content.Intent;
import androidx.core.app.AbstractC1019f;
import androidx.lifecycle.p0;
import assistantMode.enums.QuestionType$Companion;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogData;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogger;
import com.quizlet.eventlogger.model.ScanNotesPaywallEventLog;
import com.quizlet.features.infra.navigation.A;
import com.quizlet.features.onboarding.flashcards.m;
import com.quizlet.features.onboarding.flashcards.n;
import com.quizlet.features.onboarding.survey.o;
import com.quizlet.features.onboarding.survey.q;
import com.quizlet.features.paywall.PaywallActivity;
import com.quizlet.features.setpage.screenstates.s;
import com.quizlet.features.setpage.screenstates.u;
import com.quizlet.features.setpage.viewmodel.C;
import com.quizlet.features.setpage.viewmodel.C4428b;
import com.quizlet.features.setpage.viewmodel.D;
import com.quizlet.features.setpage.viewmodel.F;
import com.quizlet.features.setpage.viewmodel.InterfaceC4427a;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.features.setpage.viewmodel.z;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion;
import com.quizlet.studiablemodels.RevealSelfAssessmentStudiableQuestion;
import com.quizlet.studiablemodels.grading.StudiableQuestionResponse;
import com.quizlet.studiablemodels.grading.WrittenResponse;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import java.util.ArrayDeque;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final /* synthetic */ class a extends C4956o implements Function0 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        Object value;
        Object value2;
        int i = 0;
        int i2 = 3;
        switch (this.a) {
            case 0:
                l lVar = (l) ((i) this.receiver);
                com.google.mlkit.vision.documentscanner.internal.c cVar = lVar.b;
                cVar.getClass();
                ((EventLogger) cVar.b).l(new ScanNotesPaywallEventLog("notes_meter_exceeded", "notes_to_value_paywall_library_clicked"));
                lVar.d.j(e.b);
                return Unit.a;
            case 1:
                ((l) ((i) this.receiver)).d.j(e.c);
                return Unit.a;
            case 2:
                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar = (com.quizlet.quizletandroid.ui.navigationmanagers.e) ((com.quizlet.features.notes.manager.a) this.receiver);
                eVar.getClass();
                String str = UpgradeActivity.v;
                eVar.b(AbstractC3242q6.i(eVar.a, "notes_meter_exceeded", com.quizlet.features.infra.models.upgrade.a.v));
                return Unit.a;
            case 3:
                n nVar = (n) this.receiver;
                nVar.getClass();
                E.A(p0.j(nVar), null, null, new m(nVar, null), 3);
                return Unit.a;
            case 4:
                q qVar = (q) this.receiver;
                qVar.getClass();
                E.A(p0.j(qVar), null, null, new o(qVar, null), 3);
                return Unit.a;
            case 5:
                PaywallActivity paywallActivity = (PaywallActivity) this.receiver;
                A a = paywallActivity.i;
                if (a != null) {
                    a.i((String) paywallActivity.j.getValue(), (com.quizlet.features.infra.models.upgrade.a) paywallActivity.k.getValue(), null);
                    return Unit.a;
                }
                Intrinsics.m("upgradeNavigation");
                throw null;
            case 6:
                ((PaywallActivity) this.receiver).finish();
                return Unit.a;
            case 7:
                ((PaywallActivity) this.receiver).finish();
                return Unit.a;
            case 8:
                com.quizlet.features.questionnaire.navigation.m mVar = (com.quizlet.features.questionnaire.navigation.m) ((com.quizlet.features.questionnaire.navigation.b) this.receiver);
                ArrayDeque arrayDeque = mVar.f;
                if (arrayDeque.size() > 1) {
                    arrayDeque.removeLast();
                    mVar.B((String) arrayDeque.removeLast());
                    Boolean boolValueOf = Boolean.valueOf(arrayDeque.size() <= 1);
                    s0 s0Var = mVar.e;
                    s0Var.getClass();
                    s0Var.m(null, boolValueOf);
                }
                return Unit.a;
            case 9:
                com.quizlet.features.questiontypes.fitb.m mVar2 = (com.quizlet.features.questiontypes.fitb.m) this.receiver;
                mVar2.getClass();
                E.A(p0.j(mVar2), null, null, new com.quizlet.features.questiontypes.fitb.k(mVar2, null), 3);
                return Unit.a;
            case 10:
                com.quizlet.features.questiontypes.fitb.m mVar3 = (com.quizlet.features.questiontypes.fitb.m) this.receiver;
                mVar3.n = mVar3.b.b(mVar3.f, 1, mVar3.e);
                E.A(p0.j(mVar3), null, null, new com.quizlet.features.questiontypes.fitb.h(0L, mVar3, null), 3);
                return Unit.a;
            case 11:
                com.quizlet.features.questiontypes.mcq.l lVar2 = (com.quizlet.features.questiontypes.mcq.l) ((com.quizlet.features.questiontypes.mcq.a) this.receiver);
                lVar2.getClass();
                QuestionEventLogData.a.getClass();
                MultipleChoiceStudiableQuestion multipleChoiceStudiableQuestion = lVar2.i;
                QuestionEventLogger.DefaultImpls.a(lVar2.d, lVar2.n, "view_start", QuestionEventLogData.Companion.a(multipleChoiceStudiableQuestion), 3, null, null, null, multipleChoiceStudiableQuestion.g, lVar2.k, assistantMode.enums.k.d, 256);
                return Unit.a;
            case 12:
                com.quizlet.features.questiontypes.mcq.l lVar3 = (com.quizlet.features.questiontypes.mcq.l) ((com.quizlet.features.questiontypes.mcq.a) this.receiver);
                lVar3.getClass();
                QuestionEventLogData.a.getClass();
                QuestionEventLogger.DefaultImpls.a(lVar3.d, lVar3.n, "view_end", QuestionEventLogData.Companion.a(lVar3.i), 3, null, null, null, null, null, null, 1920);
                return Unit.a;
            case 13:
                com.quizlet.features.questiontypes.selfassessment.h hVar = (com.quizlet.features.questiontypes.selfassessment.h) this.receiver;
                hVar.getClass();
                QuestionEventLogData.a.getClass();
                RevealSelfAssessmentStudiableQuestion revealSelfAssessmentStudiableQuestion = hVar.g;
                QuestionEventLogger.DefaultImpls.a(hVar.c, hVar.q, "view_start", QuestionEventLogData.Companion.a(revealSelfAssessmentStudiableQuestion), 5, null, null, null, revealSelfAssessmentStudiableQuestion.e, A1.FLASHCARDS, assistantMode.enums.k.f, 256);
                return Unit.a;
            case 14:
                com.quizlet.features.questiontypes.selfassessment.h hVar2 = (com.quizlet.features.questiontypes.selfassessment.h) this.receiver;
                hVar2.getClass();
                QuestionEventLogData.a.getClass();
                QuestionEventLogger.DefaultImpls.a(hVar2.c, hVar2.q, "view_end", QuestionEventLogData.Companion.a(hVar2.g), 5, null, null, null, null, null, null, 1920);
                return Unit.a;
            case 15:
                com.quizlet.features.questiontypes.selfassessment.h hVar3 = (com.quizlet.features.questiontypes.selfassessment.h) this.receiver;
                hVar3.getClass();
                E.A(p0.j(hVar3), null, null, new com.quizlet.features.questiontypes.selfassessment.e(hVar3, null), 3);
                return Unit.a;
            case 16:
                com.quizlet.features.questiontypes.selfassessment.h hVar4 = (com.quizlet.features.questiontypes.selfassessment.h) this.receiver;
                hVar4.getClass();
                E.A(p0.j(hVar4), null, null, new com.quizlet.features.questiontypes.selfassessment.f(hVar4, null), 3);
                return Unit.a;
            case 17:
                ((com.quizlet.features.questiontypes.written.o) this.receiver).E();
                return Unit.a;
            case 18:
                com.quizlet.features.questiontypes.written.o oVar = (com.quizlet.features.questiontypes.written.o) this.receiver;
                com.quizlet.studiablemodels.grading.b bVar = oVar.o;
                if (bVar != null) {
                    StudiableQuestionResponse studiableQuestionResponse = bVar.a.b.a;
                    Intrinsics.e(studiableQuestionResponse, "null cannot be cast to non-null type com.quizlet.studiablemodels.grading.WrittenResponse");
                    oVar.C(com.quizlet.features.questiontypes.written.data.a.e, ((WrittenResponse) studiableQuestionResponse).a, bVar);
                }
                return Unit.a;
            case 19:
                com.quizlet.features.questiontypes.written.o oVar2 = (com.quizlet.features.questiontypes.written.o) this.receiver;
                com.quizlet.studiablemodels.grading.b bVar2 = oVar2.o;
                if (bVar2 != null) {
                    StudiableQuestionResponse studiableQuestionResponse2 = bVar2.a.b.a;
                    Intrinsics.e(studiableQuestionResponse2, "null cannot be cast to non-null type com.quizlet.studiablemodels.grading.WrittenResponse");
                    oVar2.C(com.quizlet.features.questiontypes.written.data.a.d, ((WrittenResponse) studiableQuestionResponse2).a, bVar2);
                }
                return Unit.a;
            case 20:
                ((com.quizlet.features.questiontypes.written.o) this.receiver).E();
                return Unit.a;
            case 21:
                com.quizlet.features.questiontypes.written.o oVar3 = (com.quizlet.features.questiontypes.written.o) ((com.quizlet.features.questiontypes.written.a) this.receiver);
                String str2 = oVar3.i.d;
                QuestionType$Companion questionType$Companion = assistantMode.enums.k.Companion;
                com.quizlet.features.questiontypes.written.o.D(oVar3, "view_start", null, null, str2, oVar3.j, 6);
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.features.questiontypes.written.o oVar4 = (com.quizlet.features.questiontypes.written.o) ((com.quizlet.features.questiontypes.written.a) this.receiver);
                oVar4.getClass();
                com.quizlet.features.questiontypes.written.o.D(oVar4, "view_end", null, null, null, null, 62);
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                Activity activity = (Activity) this.receiver;
                Intrinsics.checkNotNullParameter(activity, "<this>");
                Intent intentA = AbstractC1019f.a(activity);
                Intrinsics.d(intentA);
                intentA.addFlags(67108864);
                activity.startActivity(intentA);
                activity.finish();
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                P p = (P) ((InterfaceC4427a) this.receiver);
                s0 s0Var2 = p.M1;
                do {
                    value = s0Var2.getValue();
                } while (!s0Var2.k(value, u.a));
                E.A(p0.j(p), null, null, new z(p, null), 3);
                return Unit.a;
            case EventType.SUBS /* 25 */:
                s0 s0Var3 = ((P) ((InterfaceC4427a) this.receiver)).M1;
                do {
                    value2 = s0Var3.getValue();
                } while (!s0Var3.k(value2, s.a));
                return Unit.a;
            case EventType.CDN /* 26 */:
                ((com.quizlet.features.setpage.header.viewmodel.f) ((com.quizlet.features.setpage.header.viewmodel.a) this.receiver)).e.A("set_page_description_show_more_clicked");
                return Unit.a;
            case 27:
                P p2 = (P) this.receiver;
                p2.f.A("set_page_flashcards_study_mode_clicked");
                p2.H(new C(p2, null));
                return Unit.a;
            case 28:
                P p3 = (P) this.receiver;
                p3.f.A("set_page_learn_study_mode_clicked");
                p3.I(new C4428b(p3, i), new D(p3, null, null));
                return Unit.a;
            default:
                P p4 = (P) this.receiver;
                p4.f.A("set_page_test_study_mode_clicked");
                p4.I(new C4428b(p4, i2), new F(p4, null));
                return Unit.a;
        }
    }
}
