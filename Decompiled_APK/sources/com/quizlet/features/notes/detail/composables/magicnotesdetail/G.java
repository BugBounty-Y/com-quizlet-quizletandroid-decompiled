package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import android.content.Intent;
import android.os.Bundle;
import androidx.compose.animation.d0;
import androidx.lifecycle.X;
import androidx.lifecycle.p0;
import androidx.recyclerview.widget.C1372j;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.J1;
import com.google.android.gms.internal.mlkit_vision_camera.U2;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.data.model.EnumC4167t0;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.notes.common.events.C4371b;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import com.quizlet.features.questiontypes.coordinator.QuestionCoordinatorFragment;
import com.quizlet.features.questiontypes.fitb.FillInTheBlankQuestionFragment;
import com.quizlet.features.questiontypes.mcq.MultipleChoiceQuestionFragment;
import com.quizlet.features.questiontypes.selfassessment.SelfAssessmentQuestionFragment;
import com.quizlet.features.questiontypes.truefalse.TrueFalseQuestionFragment;
import com.quizlet.features.questiontypes.written.WrittenQuestionFragment;
import com.quizlet.features.setpage.data.NoNetworkConnectionException;
import com.quizlet.features.setpage.progress.presentation.ui.SetPageProgressFragment;
import com.quizlet.features.setpage.progress.presentation.ui.SetPageProgressItemView;
import com.quizlet.features.setpage.screenstates.C4422b;
import com.quizlet.features.setpage.screenstates.C4423c;
import com.quizlet.features.setpage.viewmodel.C4435i;
import com.quizlet.features.setpage.viewmodel.C4436j;
import com.quizlet.features.setpage.viewmodel.InterfaceC4427a;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.EnumC4471c0;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.FillInTheBlankStudiableQuestion;
import com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion;
import com.quizlet.studiablemodels.RevealSelfAssessmentStudiableQuestion;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.TrueFalseStudiableQuestion;
import com.quizlet.studiablemodels.WrittenStudiableQuestion;
import com.quizlet.utm.a;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class G extends C4956o implements Function1 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ G(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String strN;
        okhttp3.s sVarD;
        int i = 0;
        int i2 = 2;
        String sharedUrl = null;
        int i3 = 1;
        switch (this.a) {
            case 0:
                com.quizlet.features.notes.common.events.y p0 = (com.quizlet.features.notes.common.events.y) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                ((com.quizlet.features.notes.detail.viewmodels.v) this.receiver).F(p0);
                return Unit.a;
            case 1:
                long jLongValue = ((Number) obj).longValue();
                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar = (com.quizlet.quizletandroid.ui.navigationmanagers.e) ((com.quizlet.features.notes.manager.a) this.receiver);
                eVar.getClass();
                com.quizlet.quizletandroid.ui.navigationmanagers.e.a(eVar, jLongValue, A1.FLASHCARDS, null, null, 60);
                return Unit.a;
            case 2:
                long jLongValue2 = ((Number) obj).longValue();
                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar2 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) ((com.quizlet.features.notes.manager.a) this.receiver);
                eVar2.getClass();
                com.quizlet.quizletandroid.ui.navigationmanagers.e.a(eVar2, jLongValue2, A1.LEARNING_ASSISTANT, null, null, 60);
                return Unit.a;
            case 3:
                long jLongValue3 = ((Number) obj).longValue();
                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar3 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) ((com.quizlet.features.notes.manager.a) this.receiver);
                eVar3.getClass();
                com.quizlet.quizletandroid.ui.navigationmanagers.e.a(eVar3, jLongValue3, A1.MOBILE_SCATTER, null, null, 60);
                return Unit.a;
            case 4:
                long jLongValue4 = ((Number) obj).longValue();
                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar4 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) ((com.quizlet.features.notes.manager.a) this.receiver);
                eVar4.getClass();
                com.quizlet.quizletandroid.ui.navigationmanagers.e.a(eVar4, jLongValue4, A1.TEST, null, null, 60);
                return Unit.a;
            case 5:
                String magicNotesUuid = (String) obj;
                Intrinsics.checkNotNullParameter(magicNotesUuid, "p0");
                androidx.navigation.H h = (androidx.navigation.H) this.receiver;
                Intrinsics.checkNotNullParameter(h, "<this>");
                Intrinsics.checkNotNullParameter(magicNotesUuid, "magicNotesUuid");
                androidx.navigation.B bK = h.b.h().k("essay");
                if (bK != null) {
                    h.b(bK.b.c, AbstractC3206m6.a(new Pair("uuid", magicNotesUuid)), J1.c(new com.quizlet.features.notes.detail.navigation.c(i3, bK)));
                } else {
                    androidx.navigation.r.d(h, "essay");
                }
                return Unit.a;
            case 6:
                com.quizlet.features.notes.common.events.y event = (com.quizlet.features.notes.common.events.y) obj;
                Intrinsics.checkNotNullParameter(event, "p0");
                com.quizlet.features.notes.upload.viewmodels.e eVar5 = (com.quizlet.features.notes.upload.viewmodels.e) this.receiver;
                eVar5.getClass();
                Intrinsics.checkNotNullParameter(event, "event");
                boolean z = event instanceof com.quizlet.features.notes.common.events.A;
                C4203d c4203d = eVar5.p;
                if (z) {
                    String str = ((com.quizlet.features.notes.common.events.A) event).a;
                    eVar5.y = str;
                    kotlinx.coroutines.E.A(p0.j(eVar5), c4203d, null, new com.quizlet.features.notes.upload.viewmodels.d(eVar5, str, null), 2);
                } else if (event instanceof com.quizlet.features.notes.common.events.z) {
                    String str2 = ((com.quizlet.features.notes.common.events.z) event).a;
                    boolean z2 = eVar5.w;
                    com.quizlet.features.notes.logging.f fVar = eVar5.q;
                    if (!z2 && str2.length() < eVar5.n) {
                        fVar.getClass();
                        fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.TEXT_MORE_TEXT_NEEDED.a()));
                        eVar5.w = true;
                    } else if (!eVar5.x && str2.length() > eVar5.m) {
                        fVar.getClass();
                        fVar.a(NotesEventLog.Companion.b(NotesEventLog.b, com.quizlet.features.notes.logging.a.b, EnumC4471c0.TEXT_OVER_CHAR_LIMIT_SEEN.a()));
                        eVar5.x = true;
                    }
                } else if (event instanceof C4371b) {
                    com.quizlet.features.notes.data.x xVar = ((C4371b) event).a;
                    if (Intrinsics.b(xVar, com.quizlet.features.notes.data.p.a)) {
                        String str3 = eVar5.y;
                        eVar5.y = str3;
                        kotlinx.coroutines.E.A(p0.j(eVar5), c4203d, null, new com.quizlet.features.notes.upload.viewmodels.d(eVar5, str3, null), 2);
                    } else if (Intrinsics.b(xVar, com.quizlet.features.notes.data.q.a) || Intrinsics.b(xVar, com.quizlet.features.notes.data.g.a) || Intrinsics.b(xVar, com.quizlet.features.notes.data.n.a) || (xVar instanceof com.quizlet.features.notes.data.m)) {
                        eVar5.k.h(com.quizlet.features.notes.upload.events.a.a);
                    }
                }
                return Unit.a;
            case 7:
                com.quizlet.features.notes.common.events.y p02 = (com.quizlet.features.notes.common.events.y) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                ((com.quizlet.features.notes.upload.viewmodels.k) this.receiver).N(p02);
                return Unit.a;
            case 8:
                com.quizlet.features.onboarding.ell.l onboardingELLEvent = (com.quizlet.features.onboarding.ell.l) obj;
                Intrinsics.checkNotNullParameter(onboardingELLEvent, "p0");
                com.quizlet.features.onboarding.ell.B b = (com.quizlet.features.onboarding.ell.B) this.receiver;
                b.getClass();
                Intrinsics.checkNotNullParameter(onboardingELLEvent, "onboardingELLEvent");
                kotlinx.coroutines.E.A(p0.j(b), null, null, new com.quizlet.features.onboarding.ell.A(onboardingELLEvent, b, null), 3);
                return Unit.a;
            case 9:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                com.quizlet.features.onboarding.flashcards.n nVar = (com.quizlet.features.onboarding.flashcards.n) this.receiver;
                nVar.getClass();
                kotlinx.coroutines.E.A(p0.j(nVar), null, null, new com.quizlet.features.onboarding.flashcards.l(nVar, zBooleanValue, null), 3);
                return Unit.a;
            case 10:
                com.quizlet.features.onboarding.survey.m source = (com.quizlet.features.onboarding.survey.m) obj;
                Intrinsics.checkNotNullParameter(source, "p0");
                com.quizlet.features.onboarding.survey.q qVar = (com.quizlet.features.onboarding.survey.q) this.receiver;
                qVar.getClass();
                Intrinsics.checkNotNullParameter(source, "source");
                kotlinx.coroutines.E.A(p0.j(qVar), null, null, new com.quizlet.features.onboarding.survey.p(qVar, source, null), 3);
                return Unit.a;
            case 11:
                com.quizlet.features.practicetest.detail.data.p p03 = (com.quizlet.features.practicetest.detail.data.p) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                ((com.quizlet.features.practicetest.detail.viewmodel.i) ((com.quizlet.features.practicetest.detail.viewmodel.a) this.receiver)).C(p03);
                return Unit.a;
            case 12:
                ((com.quizlet.features.practicetest.navigation.d) this.receiver).y(((Number) obj).longValue());
                return Unit.a;
            case 13:
                com.quizlet.features.infra.models.share.a p04 = (com.quizlet.features.infra.models.share.a) obj;
                Intrinsics.checkNotNullParameter(p04, "p0");
                ((com.quizlet.features.practicetest.navigation.d) this.receiver).c(p04);
                return Unit.a;
            case 14:
                com.quizlet.ui.models.webpage.m p05 = (com.quizlet.ui.models.webpage.m) obj;
                Intrinsics.checkNotNullParameter(p05, "p0");
                ((com.quizlet.features.practicetest.navigation.d) this.receiver).D(p05);
                return Unit.a;
            case 15:
                ((com.quizlet.features.practicetest.navigation.d) this.receiver).j((Intent) obj);
                return Unit.a;
            case 16:
                ((com.quizlet.features.practicetest.navigation.d) this.receiver).r((Intent) obj);
                return Unit.a;
            case 17:
                com.quizlet.ui.models.webpage.m p06 = (com.quizlet.ui.models.webpage.m) obj;
                Intrinsics.checkNotNullParameter(p06, "p0");
                ((com.quizlet.features.practicetest.navigation.d) this.receiver).D(p06);
                return Unit.a;
            case 18:
                com.quizlet.features.practicetest.results.data.n p07 = (com.quizlet.features.practicetest.results.data.n) obj;
                Intrinsics.checkNotNullParameter(p07, "p0");
                ((com.quizlet.features.practicetest.results.viewmodel.h) ((com.quizlet.features.practicetest.results.viewmodel.a) this.receiver)).C(p07);
                return Unit.a;
            case 19:
                com.quizlet.features.practicetest.results.data.n p08 = (com.quizlet.features.practicetest.results.data.n) obj;
                Intrinsics.checkNotNullParameter(p08, "p0");
                ((com.quizlet.features.practicetest.results.viewmodel.h) ((com.quizlet.features.practicetest.results.viewmodel.a) this.receiver)).C(p08);
                return Unit.a;
            case 20:
                com.quizlet.features.practicetest.takingtest.data.y p09 = (com.quizlet.features.practicetest.takingtest.data.y) obj;
                Intrinsics.checkNotNullParameter(p09, "p0");
                ((com.quizlet.features.practicetest.takingtest.viewmodel.l) ((com.quizlet.features.practicetest.takingtest.viewmodel.a) this.receiver)).F(p09);
                return Unit.a;
            case 21:
                ShowQuestion p010 = (ShowQuestion) obj;
                Intrinsics.checkNotNullParameter(p010, "p0");
                QuestionCoordinatorFragment questionCoordinatorFragment = (QuestionCoordinatorFragment) this.receiver;
                String str4 = QuestionCoordinatorFragment.k;
                questionCoordinatorFragment.getClass();
                if (p010 instanceof ShowQuestion.MultipleChoice) {
                    ShowQuestion.MultipleChoice multipleChoice = (ShowQuestion.MultipleChoice) p010;
                    String str5 = MultipleChoiceQuestionFragment.k;
                    MultipleChoiceStudiableQuestion multipleChoiceQuestion = multipleChoice.a;
                    Intrinsics.checkNotNullParameter(multipleChoiceQuestion, "multipleChoiceQuestion");
                    QuestionSettings settings = multipleChoice.d;
                    Intrinsics.checkNotNullParameter(settings, "settings");
                    A1 studyModeType = multipleChoice.e;
                    Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
                    MultipleChoiceQuestionFragment multipleChoiceQuestionFragment = new MultipleChoiceQuestionFragment();
                    Bundle bundle = new Bundle();
                    U2.a(bundle, multipleChoice.b, multipleChoice.c, settings, studyModeType, multipleChoice.f);
                    bundle.putParcelable("ARG_STUDIABLE_QUESTION", multipleChoiceQuestion);
                    bundle.putBoolean("ARG_HAS_DIAGRAM_ANSWERS", multipleChoice.g);
                    bundle.putBoolean("ARG_DID_MISS_QUESTION", multipleChoice.h);
                    multipleChoiceQuestionFragment.setArguments(bundle);
                    questionCoordinatorFragment.T(multipleChoiceQuestionFragment, MultipleChoiceQuestionFragment.k);
                } else if (p010 instanceof ShowQuestion.TrueFalse) {
                    ShowQuestion.TrueFalse trueFalse = (ShowQuestion.TrueFalse) p010;
                    String str6 = TrueFalseQuestionFragment.k;
                    TrueFalseStudiableQuestion trueFalseQuestion = trueFalse.a;
                    Intrinsics.checkNotNullParameter(trueFalseQuestion, "trueFalseQuestion");
                    QuestionSettings settings2 = trueFalse.d;
                    Intrinsics.checkNotNullParameter(settings2, "settings");
                    A1 studyModeType2 = trueFalse.e;
                    Intrinsics.checkNotNullParameter(studyModeType2, "studyModeType");
                    TrueFalseQuestionFragment trueFalseQuestionFragment = new TrueFalseQuestionFragment();
                    Bundle bundle2 = new Bundle();
                    U2.a(bundle2, trueFalse.b, trueFalse.c, settings2, studyModeType2, trueFalse.f);
                    bundle2.putParcelable("ARG_STUDIABLE_QUESTION", trueFalseQuestion);
                    trueFalseQuestionFragment.setArguments(bundle2);
                    questionCoordinatorFragment.T(trueFalseQuestionFragment, TrueFalseQuestionFragment.k);
                } else if (p010 instanceof ShowQuestion.Written) {
                    ShowQuestion.Written written = (ShowQuestion.Written) p010;
                    String str7 = WrittenQuestionFragment.k;
                    WrittenStudiableQuestion writtenQuestion = written.a;
                    Intrinsics.checkNotNullParameter(writtenQuestion, "writtenQuestion");
                    QuestionSettings settings3 = written.d;
                    Intrinsics.checkNotNullParameter(settings3, "settings");
                    A1 studyModeType3 = written.e;
                    Intrinsics.checkNotNullParameter(studyModeType3, "studyModeType");
                    WrittenQuestionFragment writtenQuestionFragment = new WrittenQuestionFragment();
                    Bundle bundle3 = new Bundle();
                    U2.a(bundle3, written.b, written.c, settings3, studyModeType3, written.f);
                    bundle3.putParcelable("ARG_STUDIABLE_QUESTION", writtenQuestion);
                    bundle3.putSerializable("ARG_METERED_EVENT", written.g);
                    bundle3.putBoolean("ARG_DID_MISS_QUESTION", written.h);
                    writtenQuestionFragment.setArguments(bundle3);
                    questionCoordinatorFragment.T(writtenQuestionFragment, WrittenQuestionFragment.k);
                } else if (p010 instanceof ShowQuestion.SelfAssessment) {
                    ShowQuestion.SelfAssessment selfAssessment = (ShowQuestion.SelfAssessment) p010;
                    String str8 = SelfAssessmentQuestionFragment.k;
                    RevealSelfAssessmentStudiableQuestion selfAssessmentQuestion = selfAssessment.a;
                    Intrinsics.checkNotNullParameter(selfAssessmentQuestion, "selfAssessmentQuestion");
                    QuestionSettings settings4 = selfAssessment.d;
                    Intrinsics.checkNotNullParameter(settings4, "settings");
                    A1 studyModeType4 = selfAssessment.e;
                    Intrinsics.checkNotNullParameter(studyModeType4, "studyModeType");
                    SelfAssessmentQuestionFragment selfAssessmentQuestionFragment = new SelfAssessmentQuestionFragment();
                    Bundle bundle4 = new Bundle();
                    U2.a(bundle4, selfAssessment.b, selfAssessment.c, settings4, studyModeType4, false);
                    bundle4.putParcelable("ARG_STUDIABLE_QUESTION", selfAssessmentQuestion);
                    selfAssessmentQuestionFragment.setArguments(bundle4);
                    questionCoordinatorFragment.T(selfAssessmentQuestionFragment, SelfAssessmentQuestionFragment.k);
                } else if (p010 instanceof ShowQuestion.FillInTheBlank) {
                    ShowQuestion.FillInTheBlank fillInTheBlank = (ShowQuestion.FillInTheBlank) p010;
                    String str9 = FillInTheBlankQuestionFragment.k;
                    FillInTheBlankStudiableQuestion question = fillInTheBlank.a;
                    Intrinsics.checkNotNullParameter(question, "question");
                    QuestionSettings settings5 = fillInTheBlank.d;
                    Intrinsics.checkNotNullParameter(settings5, "settings");
                    A1 studyModeType5 = fillInTheBlank.e;
                    Intrinsics.checkNotNullParameter(studyModeType5, "studyModeType");
                    FillInTheBlankQuestionFragment fillInTheBlankQuestionFragment = new FillInTheBlankQuestionFragment();
                    Bundle bundle5 = new Bundle();
                    U2.a(bundle5, fillInTheBlank.b, fillInTheBlank.c, settings5, studyModeType5, false);
                    bundle5.putParcelable("ARG_STUDIABLE_QUESTION", question);
                    fillInTheBlankQuestionFragment.setArguments(bundle5);
                    questionCoordinatorFragment.T(fillInTheBlankQuestionFragment, FillInTheBlankQuestionFragment.k);
                } else if (!(p010 instanceof ShowQuestion.None)) {
                    throw new NoWhenBranchMatchedException();
                }
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                StudiableAudio audio = (StudiableAudio) obj;
                Intrinsics.checkNotNullParameter(audio, "p0");
                com.quizlet.features.questiontypes.selfassessment.h hVar = (com.quizlet.features.questiontypes.selfassessment.h) this.receiver;
                hVar.getClass();
                Intrinsics.checkNotNullParameter(audio, "audio");
                hVar.D();
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                boolean zBooleanValue2 = ((Boolean) obj).booleanValue();
                com.quizlet.features.questiontypes.selfassessment.h hVar2 = (com.quizlet.features.questiontypes.selfassessment.h) this.receiver;
                QuestionSettings questionSettings = hVar2.o;
                questionSettings.getClass();
                QuestionSettings questionSettingsA = QuestionSettings.a(questionSettings, null, null, zBooleanValue2, false, false, false, false, false, false, null, null, false, false, false, false, false, 262139);
                hVar2.o = questionSettingsA;
                if (questionSettingsA.c) {
                    hVar2.D();
                }
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                com.quizlet.features.setpage.menu.data.k setPageMenuOptions = (com.quizlet.features.setpage.menu.data.k) obj;
                Intrinsics.checkNotNullParameter(setPageMenuOptions, "p0");
                P p = (P) ((InterfaceC4427a) this.receiver);
                p.getClass();
                Intrinsics.checkNotNullParameter(setPageMenuOptions, "setPageMenuOptions");
                boolean zB = Intrinsics.b(setPageMenuOptions, com.quizlet.features.setpage.menu.data.a.a);
                com.google.firebase.messaging.p pVar = p.f;
                X x = p.j1;
                X x2 = p.i1;
                if (zB) {
                    if (p.p.p()) {
                        pVar.A("add_to_class_click_from_overflow_menu");
                        long jD = p.D();
                        com.quizlet.features.notes.a aVar = p.h;
                        aVar.getClass();
                        EventLoggerExt.c(aVar.a, new com.braze.requests.framework.m(26, jD));
                        x2.l(new com.quizlet.features.infra.basestudy.data.models.a(kotlin.collections.A.b(Long.valueOf(p.D()))));
                    } else {
                        x.l(C4422b.a);
                    }
                } else if (!Intrinsics.b(setPageMenuOptions, com.quizlet.features.setpage.menu.data.b.a)) {
                    boolean zB2 = Intrinsics.b(setPageMenuOptions, com.quizlet.features.setpage.menu.data.c.a);
                    X x3 = p.Z;
                    if (zB2) {
                        x3.l(com.quizlet.features.setpage.screenstates.w.a);
                    } else {
                        boolean zB3 = Intrinsics.b(setPageMenuOptions, com.quizlet.features.setpage.menu.data.e.a);
                        androidx.compose.ui.text.font.o oVar = p.J1;
                        if (zB3) {
                            kotlinx.coroutines.E.A(p0.j(p), oVar, null, new C4436j(p, null), 2);
                        } else if (Intrinsics.b(setPageMenuOptions, com.quizlet.features.setpage.menu.data.f.a)) {
                            if (p.G()) {
                                DBStudySet dBStudySet = p.F1;
                                if (dBStudySet == null) {
                                    Intrinsics.m("set");
                                    throw null;
                                }
                                x3.l(new com.quizlet.features.setpage.screenstates.x(dBStudySet));
                            }
                        } else if (Intrinsics.b(setPageMenuOptions, com.quizlet.features.setpage.menu.data.g.a)) {
                            kotlinx.coroutines.E.A(p0.j(p), oVar, null, new com.quizlet.features.setpage.viewmodel.I(p, false, null), 2);
                        } else if (Intrinsics.b(setPageMenuOptions, com.quizlet.features.setpage.menu.data.h.a)) {
                            x2.l(com.quizlet.features.infra.basestudy.data.models.i.a);
                        } else if (Intrinsics.b(setPageMenuOptions, com.quizlet.features.setpage.menu.data.i.a)) {
                            DBStudySet dBStudySet2 = p.F1;
                            if (dBStudySet2 == null) {
                                Intrinsics.m("set");
                                throw null;
                            }
                            Object title = dBStudySet2.getTitle();
                            if (title == null) {
                                Object[] args = new Object[0];
                                Intrinsics.checkNotNullParameter(args, "args");
                                title = new com.quizlet.qutils.string.f(R.string.this_set, C4933y.P(args));
                            }
                            Object[] args2 = {title};
                            Intrinsics.checkNotNullParameter(args2, "args");
                            x3.l(new com.quizlet.features.setpage.screenstates.y(new com.quizlet.qutils.string.f(R.string.set_page_progress_reset_confirm_title, C4933y.P(args2))));
                            EventLoggerExt.c(p.i.a, new com.quizlet.features.practicetest.navigation.a(18));
                        } else if (Intrinsics.b(setPageMenuOptions, com.quizlet.features.setpage.menu.data.j.a)) {
                            if (p.G()) {
                                a.b bVarEncodeUriParams = com.quizlet.utm.a.encodeUriParams(new a.C0023a(new a.c(com.quizlet.utm.campaigns.b.SET_PAGE_SHARE, com.quizlet.utm.mediums.b.SHARE_LINK, com.quizlet.utm.sources.b.SHARE_SHEET_ANDROID), Long.valueOf(p.k.getPersonId())));
                                DBStudySet dBStudySet3 = p.F1;
                                if (dBStudySet3 == null) {
                                    Intrinsics.m("set");
                                    throw null;
                                }
                                if (dBStudySet3.getWebUrl() != null) {
                                    DBStudySet dBStudySet4 = p.F1;
                                    if (dBStudySet4 == null) {
                                        Intrinsics.m("set");
                                        throw null;
                                    }
                                    strN = dBStudySet4.getWebUrl();
                                } else {
                                    DBStudySet dBStudySet5 = p.F1;
                                    if (dBStudySet5 == null) {
                                        Intrinsics.m("set");
                                        throw null;
                                    }
                                    strN = d0.n(dBStudySet5.getSetId(), "https://quizlet.com/");
                                }
                                if (strN != null) {
                                    Intrinsics.checkNotNullParameter(strN, "<this>");
                                    try {
                                        Intrinsics.checkNotNullParameter(strN, "<this>");
                                        C1372j c1372j = new C1372j();
                                        c1372j.l(null, strN);
                                        sVarD = c1372j.d();
                                    } catch (IllegalArgumentException unused) {
                                        sVarD = null;
                                    }
                                    if (sVarD != null) {
                                        C1372j c1372jF = sVarD.f();
                                        c1372jF.c("x", bVarEncodeUriParams.getUtmBlob());
                                        c1372jF.c("i", bVarEncodeUriParams.getUserId());
                                        sharedUrl = c1372jF.d().i;
                                    }
                                }
                            }
                            if (sharedUrl != null) {
                                pVar.getClass();
                                Intrinsics.checkNotNullParameter(sharedUrl, "sharedUrl");
                                ((EventLogger) pVar.b).C(sharedUrl);
                            }
                            if (!p.G() || p.D() <= 0) {
                                Object[] args3 = new Object[0];
                                Intrinsics.checkNotNullParameter(args3, "args");
                                p.p1.l(new com.quizlet.features.infra.snackbar.m(new com.quizlet.qutils.string.f(R.string.cannot_complete_action, C4933y.P(args3))));
                            } else {
                                io.reactivex.rxjava3.internal.operators.single.g gVarE = p.E().e(new com.google.firebase.messaging.p(p, 22));
                                Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
                                io.reactivex.rxjava3.internal.observers.e eVarI = gVarE.i(new C4435i(p, 4), io.reactivex.rxjava3.internal.functions.d.e);
                                Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                                Intrinsics.checkNotNullParameter(eVarI, "<this>");
                                p.A(eVarI);
                            }
                        } else {
                            if (!Intrinsics.b(setPageMenuOptions, com.quizlet.features.setpage.menu.data.d.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            x2.j(com.quizlet.features.infra.basestudy.data.models.f.a);
                        }
                    }
                } else if (!((com.quizlet.remote.connectivity.b) p.q).a().a) {
                    x.l(new C4423c(R.string.copy_set_offline_error));
                    timber.log.a aVar2 = timber.log.c.a;
                    Intrinsics.checkNotNullParameter("User does not have network connection", "msg");
                    aVar2.e(new NoNetworkConnectionException("User does not have network connection"));
                } else if (p.G()) {
                    DBStudySet dBStudySet6 = p.F1;
                    if (dBStudySet6 == null) {
                        Intrinsics.m("set");
                        throw null;
                    }
                    long id = dBStudySet6.getId();
                    com.quizlet.data.repository.folderwithcreatorinclass.e eVar6 = p.o;
                    io.reactivex.rxjava3.internal.operators.single.k kVarH = ((IQuizletApiClient) eVar6.a).n(id).l((io.reactivex.rxjava3.core.o) eVar6.e).e(com.quizlet.infra.legacysyncengine.net.api.a.b).e(new com.google.firebase.messaging.p(eVar6, 23)).h((io.reactivex.rxjava3.core.o) eVar6.d);
                    Intrinsics.checkNotNullExpressionValue(kVarH, "observeOn(...)");
                    io.reactivex.rxjava3.internal.observers.e eVarI2 = new io.reactivex.rxjava3.internal.operators.single.e(new io.reactivex.rxjava3.internal.operators.single.d(kVarH, new C4435i(p, i), i3), new com.quizlet.eventlogger.e(p, 10), i3).i(new C4435i(p, i3), new C4435i(p, i2));
                    Intrinsics.checkNotNullExpressionValue(eVarI2, "subscribe(...)");
                    Intrinsics.checkNotNullParameter(eVarI2, "<this>");
                    p.A(eVarI2);
                }
                return Unit.a;
            case EventType.SUBS /* 25 */:
                long jLongValue5 = ((Number) obj).longValue();
                com.quizlet.features.setpage.header.viewmodel.f fVar2 = (com.quizlet.features.setpage.header.viewmodel.f) ((com.quizlet.features.setpage.header.viewmodel.a) this.receiver);
                fVar2.getClass();
                kotlinx.coroutines.E.A(p0.j(fVar2), null, null, new com.quizlet.features.setpage.header.viewmodel.e(fVar2, jLongValue5, null), 3);
                return Unit.a;
            case EventType.CDN /* 26 */:
                com.quizlet.features.setpage.progress.b p011 = (com.quizlet.features.setpage.progress.b) obj;
                Intrinsics.checkNotNullParameter(p011, "p0");
                SetPageProgressFragment setPageProgressFragment = (SetPageProgressFragment) this.receiver;
                String str10 = SetPageProgressFragment.l;
                com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = ((com.quizlet.features.setpage.databinding.c) setPageProgressFragment.J()).b;
                SetPageProgressItemView progressItemNotStarted = (SetPageProgressItemView) fVar3.e;
                Intrinsics.checkNotNullExpressionValue(progressItemNotStarted, "progressItemNotStarted");
                setPageProgressFragment.V(progressItemNotStarted, p011);
                SetPageProgressItemView progressItemLearning = (SetPageProgressItemView) fVar3.c;
                Intrinsics.checkNotNullExpressionValue(progressItemLearning, "progressItemLearning");
                setPageProgressFragment.V(progressItemLearning, p011);
                SetPageProgressItemView progressItemMastered = (SetPageProgressItemView) fVar3.d;
                Intrinsics.checkNotNullExpressionValue(progressItemMastered, "progressItemMastered");
                setPageProgressFragment.V(progressItemMastered, p011);
                com.quizlet.features.setpage.progress.presentation.viewmodel.a aVar3 = (com.quizlet.features.setpage.progress.presentation.viewmodel.a) setPageProgressFragment.j.getValue();
                aVar3.g.g();
                com.quizlet.features.setpage.progress.b progressData = (com.quizlet.features.setpage.progress.b) aVar3.h.d();
                if (progressData != null && progressData.b() != 0) {
                    com.features.flashcards.creatormarketing.h hVar3 = aVar3.d;
                    hVar3.getClass();
                    Intrinsics.checkNotNullParameter(progressData, "progressData");
                    EventLoggerExt.c(hVar3.a, new com.quizlet.features.setpage.header.ui.g(i3, hVar3, progressData));
                }
                return Unit.a;
            case 27:
                ((timber.log.a) this.receiver).e((Throwable) obj);
                return Unit.a;
            case 28:
                EnumC4167t0 p012 = (EnumC4167t0) obj;
                Intrinsics.checkNotNullParameter(p012, "p0");
                ((com.quizlet.features.settings.viewmodels.I) ((com.quizlet.features.settings.viewmodels.p) this.receiver)).v(p012);
                return Unit.a;
            default:
                com.quizlet.features.settings.data.models.b requestType = (com.quizlet.features.settings.data.models.b) obj;
                Intrinsics.checkNotNullParameter(requestType, "p0");
                com.quizlet.features.settings.viewmodels.u uVar = (com.quizlet.features.settings.viewmodels.u) ((com.quizlet.features.settings.viewmodels.o) this.receiver);
                uVar.getClass();
                Intrinsics.checkNotNullParameter(requestType, "requestType");
                uVar.f = requestType;
                uVar.D();
                return Unit.a;
        }
    }
}
