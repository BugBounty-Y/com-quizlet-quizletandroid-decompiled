package com.quizlet.features.questionnaire.screens;

import android.content.Context;
import android.content.Intent;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.lifecycle.p0;
import androidx.navigation.H;
import assistantMode.enums.m;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3170i6;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.model.C0;
import com.quizlet.data.model.D0;
import com.quizlet.data.model.E0;
import com.quizlet.data.model.EnumC4164s0;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogData;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogger;
import com.quizlet.eventlogger.features.revisioncenter.RevisionCenterSource;
import com.quizlet.features.infra.models.Creator;
import com.quizlet.features.questionnaire.navigation.Control;
import com.quizlet.features.questionnaire.navigation.StepModel;
import com.quizlet.features.questionnaire.navigation.o;
import com.quizlet.features.questionnaire.navigation.p;
import com.quizlet.features.questiontypes.written.q;
import com.quizlet.features.questiontypes.written.r;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.features.setpage.viewmodel.t;
import com.quizlet.features.settings.viewmodels.C4444b;
import com.quizlet.features.settings.viewmodels.u;
import com.quizlet.features.universaluploadflow.data.L;
import com.quizlet.generated.enums.S0;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.library.data.C4647a;
import com.quizlet.quizletandroid.ui.login.FacebookAuthActivity;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.S;
import com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.y;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.z;
import com.quizlet.studiablemodels.RevealSelfAssessmentStudiableQuestion;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableQuestionMetadata;
import com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer;
import com.quizlet.studiablemodels.grading.StudiableQuestionResponse;
import com.quizlet.studiablemodels.grading.WrittenResponse;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ c(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        m mVar;
        s0 s0Var;
        Object value;
        r rVar;
        Object obj = this.c;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                Control.Button button = ((StepModel.Intro) obj).d;
                String payload = button.e;
                com.quizlet.features.questionnaire.steps.b bVar = (com.quizlet.features.questionnaire.steps.b) obj2;
                bVar.getClass();
                Intrinsics.checkNotNullParameter(payload, "payload");
                com.quizlet.data.interactor.course.a aVar = bVar.c;
                aVar.getClass();
                Intrinsics.checkNotNullParameter(payload, "payload");
                ((com.quizlet.usecase.a) ((com.quizlet.usecase.b) aVar.b)).a(new o(payload, button.c));
                return Unit.a;
            case 1:
                Control.Button button2 = (Control.Button) obj;
                String payload2 = button2.e;
                com.quizlet.features.questionnaire.steps.c cVar = (com.quizlet.features.questionnaire.steps.c) obj2;
                cVar.getClass();
                Intrinsics.checkNotNullParameter(payload2, "payload");
                com.quizlet.data.interactor.course.a aVar2 = cVar.c;
                aVar2.getClass();
                Intrinsics.checkNotNullParameter(payload2, "payload");
                ((com.quizlet.usecase.a) ((com.quizlet.usecase.b) aVar2.b)).a(new p(payload2, button2.c));
                return Unit.a;
            case 2:
                ((com.quizlet.features.questiontypes.mcq.l) ((com.quizlet.features.questiontypes.mcq.a) obj2)).B(com.quizlet.features.questiontypes.mcq.r.a);
                ((InterfaceC0773a0) obj).setValue(Boolean.FALSE);
                return Unit.a;
            case 3:
                ((Function1) obj2).invoke((StudiableAudio) obj);
                return Unit.a;
            case 4:
                ((InterfaceC0773a0) obj).setValue(Boolean.TRUE);
                com.quizlet.features.questiontypes.selfassessment.h hVar = (com.quizlet.features.questiontypes.selfassessment.h) obj2;
                com.quizlet.features.infra.basestudy.data.models.onboarding.a aVar3 = hVar.d;
                if (!aVar3.a.getBoolean("PREF_SEEN_TAP_TO_FLIP_ONBOARDING", false)) {
                    assistantMode.refactored.a.p(aVar3.a, "PREF_SEEN_TAP_TO_FLIP_ONBOARDING", true);
                }
                com.quizlet.features.infra.models.flashcards.h hVar2 = hVar.n;
                hVar2.getClass();
                com.quizlet.features.infra.models.flashcards.h hVar3 = com.quizlet.features.infra.models.flashcards.h.a;
                if (hVar2 == hVar3) {
                    hVar3 = com.quizlet.features.infra.models.flashcards.h.b;
                }
                hVar.n = hVar3;
                hVar.e.b(true);
                if (hVar.o.c) {
                    hVar.D();
                }
                QuestionEventLogData.a.getClass();
                RevealSelfAssessmentStudiableQuestion revealSelfAssessmentStudiableQuestion = hVar.g;
                QuestionEventLogData questionEventLogDataA = QuestionEventLogData.Companion.a(revealSelfAssessmentStudiableQuestion);
                int iOrdinal = hVar.n.ordinal();
                StudiableQuestionMetadata studiableQuestionMetadata = revealSelfAssessmentStudiableQuestion.d;
                if (iOrdinal == 0) {
                    mVar = studiableQuestionMetadata.c;
                } else {
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    mVar = studiableQuestionMetadata.d;
                }
                QuestionEventLogger.DefaultImpls.a(hVar.c, hVar.q, "reveal", questionEventLogDataA, 5, null, null, AbstractC3106b5.g(mVar), null, null, null, 1920);
                return Unit.a;
            case 5:
                StudiableQuestionResponse studiableQuestionResponse = ((StudiableQuestionGradedAnswer) obj).b.b;
                Intrinsics.e(studiableQuestionResponse, "null cannot be cast to non-null type com.quizlet.studiablemodels.grading.WrittenResponse");
                com.quizlet.features.questiontypes.written.o oVar = (com.quizlet.features.questiontypes.written.o) obj2;
                oVar.getClass();
                String string = ((WrittenResponse) studiableQuestionResponse).a;
                Intrinsics.checkNotNullParameter(string, "expectedAnswer");
                oVar.x = true;
                do {
                    s0Var = oVar.p;
                    value = s0Var.getValue();
                    rVar = (r) value;
                    Intrinsics.e(rVar, "null cannot be cast to non-null type com.quizlet.features.questiontypes.written.WrittenUiState.ViewState");
                    Intrinsics.checkNotNullParameter(string, "string");
                } while (!s0Var.k(value, q.a((q) rVar, new com.quizlet.features.questiontypes.written.data.f(new com.quizlet.features.questiontypes.written.ui.i(new com.quizlet.qutils.string.e(string), 765), Integer.valueOf(R.string.copy_correct_answer)), com.quizlet.features.questiontypes.basequestion.data.a.a, null, null)));
                return Unit.a;
            case 6:
                ((Function1) obj2).invoke(Long.valueOf(((Creator) obj).a));
                return Unit.a;
            case 7:
                P p = (P) obj2;
                E.A(p0.j(p), null, null, new t(p, (com.quizlet.features.infra.folder.menu.data.q) obj, null), 3);
                return Unit.a;
            case 8:
                com.quizlet.features.settings.data.models.f reAuthType = (com.quizlet.features.settings.data.models.f) obj2;
                Intrinsics.checkNotNullParameter(reAuthType, "reAuthType");
                androidx.navigation.r.d((H) obj, D.o("deleteAccount/{reauthType}", "{reauthType}", reAuthType.name(), false));
                return Unit.a;
            case 9:
                ((Function1) obj2).invoke((com.quizlet.themes.nighttheme.a) obj);
                return Unit.a;
            case 10:
                ((C4444b) ((com.quizlet.features.settings.viewmodels.l) obj2)).B((String) ((InterfaceC0773a0) obj).getValue());
                return Unit.a;
            case 11:
                androidx.compose.ui.focus.h.a((androidx.compose.ui.focus.h) obj2);
                ((Function0) obj).invoke();
                return Unit.a;
            case 12:
                ((u) ((com.quizlet.features.settings.viewmodels.o) obj2)).C((String) ((InterfaceC0773a0) obj).getValue());
                return Unit.a;
            case 13:
                com.quizlet.data.interactor.folderwithcreator.m mVar2 = (com.quizlet.data.interactor.folderwithcreator.m) obj2;
                ((x) mVar2.d).c();
                ((x) mVar2.c).c();
                ((x) mVar2.e).c();
                u uVar = (u) ((com.quizlet.features.settings.viewmodels.o) obj);
                uVar.f = null;
                uVar.D();
                return Unit.a;
            case 14:
                com.quizlet.quizletandroid.ui.navigationmanagers.h hVar4 = (com.quizlet.quizletandroid.ui.navigationmanagers.h) obj;
                hVar4.getClass();
                ((androidx.activity.compose.o) obj2).a(new Intent(hVar4.a, (Class<?>) FacebookAuthActivity.class));
                return Unit.a;
            case 15:
                ((Function1) obj2).invoke((L) obj);
                return Unit.a;
            case 16:
                ((com.quizlet.features.universaluploadflow.navigation.e) obj2).b("universal_upload_meter_exceeded", com.quizlet.features.infra.models.upgrade.a.y);
                ((Function0) obj).invoke();
                return Unit.a;
            case 17:
                com.quizlet.learn.ads.h listener = (com.quizlet.learn.ads.h) obj2;
                com.quizlet.learn.ads.f fVar = listener.a;
                com.google.mlkit.common.sdkinternal.model.a aVar4 = com.quizlet.ads.c.b;
                boolean zI = AbstractC3170i6.i((Context) obj);
                Intrinsics.checkNotNullParameter(listener, "listener");
                fVar.h = listener;
                fVar.g = R.string.learn_mode_ad_unit_AndroidInterstitialLearnModeCheckpoint;
                fVar.f = zI;
                com.quizlet.ads.c.b.getClass();
                fVar.i = com.google.mlkit.common.sdkinternal.model.a.r(R.string.learn_mode_ad_unit_AndroidInterstitialLearnModeCheckpoint);
                fVar.b();
                return Unit.a;
            case 18:
                ((Function1) obj2).invoke((WrittenQuestionGradingOption) obj);
                return Unit.a;
            case 19:
                ((com.quizlet.learn.viewmodel.i) obj2).B(com.quizlet.learn.data.onboarding.g.a);
                ((Function0) obj).invoke();
                return Unit.a;
            case 20:
                com.quizlet.login.magiclink.viewmodel.j jVar = (com.quizlet.login.magiclink.viewmodel.j) ((com.quizlet.login.magiclink.viewmodel.b) obj2);
                String email = (String) obj;
                Intrinsics.checkNotNullParameter(email, "email");
                E.A(p0.j(jVar), null, null, new com.quizlet.login.magiclink.viewmodel.i(jVar, email, null), 3);
                return Unit.a;
            case 21:
                e0.w((InterfaceC4992i) obj2, ((com.quizlet.quizletandroid.u) obj).Q());
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                ((Function1) obj2).invoke(Long.valueOf(((C4647a) obj).a));
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                ((Function1) obj2).invoke((com.quizlet.quizletandroid.ui.globalnav.data.k) obj);
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                ((Function1) obj2).invoke((EnumC4164s0) obj);
                return Unit.a;
            case EventType.SUBS /* 25 */:
                Y y = (Y) obj2;
                S0 s0 = (S0) obj;
                y.x.a(s0, RevisionCenterSource.a);
                y.r1.j(new y(new com.quizlet.ui.models.webpage.j(s0)));
                return Unit.a;
            case EventType.CDN /* 26 */:
                com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L l = ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.i) obj2).c;
                if (l != null) {
                    String id = ((D0) obj).b;
                    Intrinsics.checkNotNullParameter(id, "isbn");
                    l.p.h(new com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.y(id));
                    com.quizlet.quizletandroid.ui.startpage.nav2.logging.a aVar5 = l.i;
                    aVar5.getClass();
                    Intrinsics.checkNotNullParameter(id, "id");
                    com.quizlet.quizletandroid.ui.startpage.nav2.logging.a.b(aVar5, "clicked_explanations", "explanations", id, 14);
                }
                return Unit.a;
            case 27:
                com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L l2 = ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.i) obj2).c;
                if (l2 != null) {
                    String uuid = ((C0) obj).d;
                    Intrinsics.checkNotNullParameter(uuid, "questionId");
                    l2.p.h(new com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.u(uuid));
                    com.quizlet.quizletandroid.ui.startpage.nav2.logging.a aVar6 = l2.i;
                    aVar6.getClass();
                    Intrinsics.checkNotNullParameter(uuid, "uuid");
                    com.quizlet.quizletandroid.ui.startpage.nav2.logging.a.b(aVar6, "clicked_explanations", "explanations", uuid, 16);
                }
                return Unit.a;
            case 28:
                com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L l3 = ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.i) obj2).c;
                if (l3 != null) {
                    String id2 = ((E0) obj).b;
                    Intrinsics.checkNotNullParameter(id2, "exerciseId");
                    l3.p.h(new z(id2));
                    com.quizlet.quizletandroid.ui.startpage.nav2.logging.a aVar7 = l3.i;
                    aVar7.getClass();
                    Intrinsics.checkNotNullParameter(id2, "id");
                    com.quizlet.quizletandroid.ui.startpage.nav2.logging.a.b(aVar7, "clicked_explanations", "explanations", id2, 15);
                }
                return Unit.a;
            default:
                com.quizlet.quizletandroid.ui.startpage.nav2.adapters.r rVar2 = (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.r) obj2;
                S s = (S) obj;
                DBStudySet studySet = s.d;
                String modelId = String.valueOf(studySet.getSetId());
                Y y2 = rVar2.d;
                y2.getClass();
                Intrinsics.checkNotNullParameter(modelId, "modelId");
                y2.j.d(1, modelId);
                Y y3 = rVar2.c;
                y3.getClass();
                Intrinsics.checkNotNullParameter(studySet, "dbStudySet");
                if (studySet.getIsCreated()) {
                    com.quizlet.offline.managers.i iVar = (com.quizlet.offline.managers.i) y3.n;
                    iVar.getClass();
                    Intrinsics.checkNotNullParameter(studySet, "studySet");
                    long id3 = studySet.getId();
                    DBUser creator = studySet.getCreator();
                    io.reactivex.rxjava3.internal.observers.e eVarI = iVar.a(id3, creator != null ? creator.getIsVerified() : false).i(new com.quizlet.billing.manager.b(17, y3, studySet), new com.quizlet.billing.manager.d(timber.log.c.a, 14));
                    Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                    Intrinsics.checkNotNullParameter(eVarI, "<this>");
                    y3.A(eVarI);
                } else {
                    y3.r1.j(new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.b(studySet.getSetId()));
                }
                long id4 = studySet.getId();
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.a aVar8 = y3.v;
                aVar8.getClass();
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.a.b(aVar8, "clicked_sets", s.i ? "recommendations" : "set", String.valueOf(id4), 1);
                return Unit.a;
        }
    }

    public /* synthetic */ c(com.quizlet.learn.ads.h hVar, Context context) {
        this.a = 17;
        com.google.mlkit.common.sdkinternal.model.a aVar = com.quizlet.ads.c.b;
        this.b = hVar;
        this.c = context;
    }
}
