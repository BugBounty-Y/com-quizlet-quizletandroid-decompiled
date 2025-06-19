package com.quizlet.quizletandroid.ui.studymodes.assistant;

import android.content.Intent;
import android.os.Bundle;
import androidx.compose.ui.platform.ComposeView;
import androidx.lifecycle.p0;
import com.airbnb.lottie.EnumC1466f;
import com.airbnb.lottie.LottieAnimationView;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3110c0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3675m6;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.ads.data.AdDataType;
import com.quizlet.ads.ui.activity.AdsActivity;
import com.quizlet.features.flashcards.FlashcardsActivity;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.features.infra.basestudy.data.models.r;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import com.quizlet.generated.enums.A1;
import com.quizlet.learn.data.B;
import com.quizlet.learn.data.C;
import com.quizlet.learn.data.C4544i;
import com.quizlet.learn.data.C4545j;
import com.quizlet.learn.data.C4546k;
import com.quizlet.learn.data.C4547l;
import com.quizlet.learn.data.C4548m;
import com.quizlet.learn.data.C4549n;
import com.quizlet.learn.data.C4553p;
import com.quizlet.learn.data.D;
import com.quizlet.learn.data.E;
import com.quizlet.learn.data.F;
import com.quizlet.learn.data.G;
import com.quizlet.learn.data.H;
import com.quizlet.learn.data.I;
import com.quizlet.learn.data.J;
import com.quizlet.learn.data.K;
import com.quizlet.learn.data.L;
import com.quizlet.learn.data.LearnRoundSummaryData;
import com.quizlet.learn.data.M;
import com.quizlet.learn.data.N;
import com.quizlet.learn.data.q;
import com.quizlet.learn.data.s;
import com.quizlet.learn.data.t;
import com.quizlet.learn.data.x;
import com.quizlet.learn.settings.data.LearnSettingsResult;
import com.quizlet.learn.viewmodel.w;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4609m;
import com.quizlet.quizletandroid.ui.learnpaywall.LearnPaywallFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.LAResultsFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.LearnCheckpointFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.LearnEndingFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.LearnRoundSummaryFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.LearnSettingsActivity;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsIntentData;
import com.quizlet.quizletandroid.ui.studymodes.testmode.activities.TestStudyModeActivity;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeActivity;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import com.quizlet.studiablemodels.StudiableCheckpoint;
import com.quizlet.studiablemodels.StudiableMeteringData;
import com.quizlet.studiablemodels.StudiableTotalProgress;
import com.quizlet.uicommon.ui.common.dialogs.ConfirmationModalFragment;
import com.quizlet.uicommon.ui.common.dialogs.QAlertDialogFragment;
import com.quizlet.uicommon.ui.common.dialogs.info.InfoModalButtonState;
import com.quizlet.uicommon.ui.common.dialogs.info.InfoModalFragment;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import java.util.Collections;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ LearningAssistantActivity b;

    public /* synthetic */ c(LearningAssistantActivity learningAssistantActivity, int i) {
        this.a = i;
        this.b = learningAssistantActivity;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = 0;
        int i2 = 1;
        LearningAssistantActivity learningAssistantActivity = this.b;
        switch (this.a) {
            case 0:
                String str = LearningAssistantActivity.D;
                if (!Intrinsics.b((x) obj, x.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                learningAssistantActivity.setResult(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF);
                learningAssistantActivity.finish();
                return Unit.a;
            case 1:
                N n = (N) obj;
                String str2 = LearningAssistantActivity.D;
                boolean z = n instanceof E;
                LearningAssistantActivity context = this.b;
                if (z) {
                    E e = (E) n;
                    if (e.g) {
                        u uVar = context.s;
                        ((ComposeView) uVar.getValue()).setVisibility(0);
                        ((ComposeView) uVar.getValue()).setContent(new androidx.compose.runtime.internal.d(true, 2000112704, new g(context, e, i2)));
                        com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i iVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) context.z.getValue();
                        iVar.getClass();
                        kotlinx.coroutines.E.A(p0.j(iVar), null, null, new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.g(iVar, null), 3);
                    } else {
                        String str3 = LearnSettingsActivity.i;
                        StudyableModelData studyableModelData = e.b;
                        String str4 = e.e;
                        LearnSettingsIntentData intentData = new LearnSettingsIntentData(e.f, e.c, studyableModelData, e.a, str4, e.d);
                        Intrinsics.checkNotNullParameter(context, "context");
                        Intrinsics.checkNotNullParameter(intentData, "intentData");
                        Intent intent = new Intent(context, (Class<?>) LearnSettingsActivity.class);
                        intent.putExtra("learnSettingsIntentData", intentData);
                        androidx.activity.result.b bVar = context.C;
                        if (bVar == null) {
                            Intrinsics.m("learnSettingsResultLauncher");
                            throw null;
                        }
                        bVar.a(intent);
                    }
                } else if (n instanceof D) {
                    D d = (D) n;
                    com.quizlet.learn.viewmodel.i iVarC0 = context.c0();
                    com.quizlet.features.infra.studysetting.managers.a manager = d.b;
                    iVarC0.getClass();
                    Intrinsics.checkNotNullParameter(manager, "manager");
                    iVarC0.d = manager;
                    context.c0().l = d.c;
                    u uVar2 = context.t;
                    ((ComposeView) uVar2.getValue()).setVisibility(0);
                    ((ComposeView) uVar2.getValue()).setContent(new androidx.compose.runtime.internal.d(true, 1041892927, new f(d, context, i2)));
                    com.quizlet.learn.viewmodel.i iVarC02 = context.c0();
                    iVarC02.getClass();
                    kotlinx.coroutines.E.A(p0.j(iVarC02), null, null, new com.quizlet.learn.viewmodel.h(iVarC02, null), 3);
                } else if (n instanceof B) {
                    AdDataType adsDataType = ((B) n).a;
                    String str5 = AdsActivity.u;
                    Intrinsics.checkNotNullParameter(context, "context");
                    Intrinsics.checkNotNullParameter(adsDataType, "adsDataType");
                    Intent intent2 = new Intent(context, (Class<?>) AdsActivity.class);
                    intent2.putExtra("ad_data_extra", adsDataType);
                    androidx.activity.result.b bVar2 = context.A;
                    if (bVar2 == null) {
                        Intrinsics.m("adsResultLauncher");
                        throw null;
                    }
                    bVar2.a(intent2);
                } else if (n instanceof I) {
                    I i3 = (I) n;
                    i3.getClass();
                    context.startActivity(WriteModeActivity.T(context, 0, Long.valueOf(i3.a), i3.b, Long.valueOf(i3.c), i3.d, i3.e));
                    context.finish();
                } else if (n instanceof H) {
                    H h = (H) n;
                    h.getClass();
                    context.startActivity(AbstractC3675m6.b(context, 0, new StudyableModelData.StudySet(h.a), h.b, h.c, h.e, 1, null, h.f, false));
                    context.finish();
                } else if (n instanceof L) {
                    L l = (L) n;
                    String title = AbstractC3053s1.e(l.a, context);
                    String description = AbstractC3053s1.e(l.b, context);
                    String actionText = AbstractC3053s1.e(l.c, context);
                    String cancelText = AbstractC3053s1.e(l.d, context);
                    Intrinsics.checkNotNullParameter(title, "title");
                    Intrinsics.checkNotNullParameter(description, "description");
                    Intrinsics.checkNotNullParameter(actionText, "actionText");
                    Intrinsics.checkNotNullParameter(cancelText, "cancelText");
                    ConfirmationModalFragment confirmationModalFragment = new ConfirmationModalFragment();
                    Bundle bundle = new Bundle();
                    bundle.putString("ARG_TITLE", title);
                    bundle.putString("ARG_DESCRIPTION", description);
                    bundle.putString("ARG_ACTION_TEXT", actionText);
                    bundle.putString("ARG_CANCEL_TEXT", cancelText);
                    confirmationModalFragment.setArguments(bundle);
                    confirmationModalFragment.F = new d(l, i);
                    confirmationModalFragment.G = new d(l, i2);
                    confirmationModalFragment.O(context.getSupportFragmentManager(), "ConfirmationModalFragment");
                } else if (n instanceof M) {
                    M m = (M) n;
                    String title2 = AbstractC3053s1.e(m.a, context);
                    String description2 = AbstractC3053s1.e(m.b, context);
                    String buttonText = AbstractC3053s1.e(m.c, context);
                    Intrinsics.checkNotNullParameter(title2, "title");
                    Intrinsics.checkNotNullParameter(description2, "description");
                    Intrinsics.checkNotNullParameter(buttonText, "buttonText");
                    InfoModalButtonState.Primary buttonState = InfoModalButtonState.Primary.a;
                    Intrinsics.checkNotNullParameter(buttonState, "buttonState");
                    InfoModalFragment infoModalFragment = new InfoModalFragment();
                    Bundle bundle2 = new Bundle();
                    bundle2.putCharSequence("ARG_TITLE", title2);
                    bundle2.putCharSequence("ARG_DESCRIPTION", description2);
                    bundle2.putCharSequence("ARG_BUTTON_TEXT", buttonText);
                    bundle2.putBoolean("ARG_SKIP_COLLAPSED", false);
                    bundle2.putParcelable("ARG_BUTTON_STATE", buttonState);
                    infoModalFragment.setArguments(bundle2);
                    com.quizlet.login.magiclink.ui.e dismissListener = new com.quizlet.login.magiclink.ui.e(m, 29);
                    Intrinsics.checkNotNullParameter(dismissListener, "dismissListener");
                    infoModalFragment.F = dismissListener;
                    infoModalFragment.O(context.getSupportFragmentManager(), "InfoModalDialogFragment");
                } else if (Intrinsics.b(n, G.a)) {
                    String str6 = UpgradeActivity.v;
                    Intent intentI = AbstractC3242q6.i(context, "learn_toast", com.quizlet.features.infra.models.upgrade.a.s);
                    androidx.activity.result.b bVar3 = context.B;
                    if (bVar3 == null) {
                        Intrinsics.m("meteringToastUpgradeResultLauncher");
                        throw null;
                    }
                    bVar3.a(intentI);
                } else if (n instanceof C) {
                    C c = (C) n;
                    String str7 = FlashcardsActivity.j;
                    int i4 = c.a;
                    String str8 = c.d;
                    context.startActivity(AbstractC3110c0.c(context, new r(i4, c.c, c.b, str8, null, c.e)));
                    context.finish();
                } else if (n instanceof F) {
                    F f = (F) n;
                    String str9 = TestStudyModeActivity.v;
                    context.startActivity(com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a.b(context, f.a, f.b, f.c, f.d, f.f, f.e, false));
                    context.finish();
                } else if (Intrinsics.b(n, K.a)) {
                    context.getIntent().removeExtra("termsToShowIntent");
                    context.startActivity(context.getIntent());
                    context.finish();
                } else {
                    if (!Intrinsics.b(n, J.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    com.facebook.internal.K k = new com.facebook.internal.K(context, 4);
                    com.quizlet.explanations.questiondetail.ui.d dVar = new com.quizlet.explanations.questiondetail.ui.d(context, 3);
                    Intrinsics.checkNotNullParameter(context, "context");
                    String message = context.getString(R.string.set_page_feature_offline_blocked_description);
                    Intrinsics.checkNotNullExpressionValue(message, "getString(...)");
                    Intrinsics.checkNotNullParameter(message, "message");
                    String title3 = context.getString(R.string.set_page_feature_offline_blocked_title);
                    Intrinsics.checkNotNullExpressionValue(title3, "getString(...)");
                    Intrinsics.checkNotNullParameter(title3, "title");
                    String text = context.getString(R.string.got_it);
                    Intrinsics.checkNotNullExpressionValue(text, "getString(...)");
                    Intrinsics.checkNotNullParameter(text, "text");
                    com.quizlet.uicommon.ui.common.dialogs.i iVar2 = new com.quizlet.uicommon.ui.common.dialogs.i(new QAlertDialogFragment.DialogData(message, title3, text, null, true, null), dVar, null, k);
                    String str10 = QAlertDialogFragment.t;
                    com.quizlet.uicommon.ui.common.dialogs.h.a(iVar2).O(context.getSupportFragmentManager(), QAlertDialogFragment.t);
                }
                return Unit.a;
            case 2:
                com.quizlet.features.questiontypes.basequestion.data.b bVar4 = (com.quizlet.features.questiontypes.basequestion.data.b) obj;
                String str11 = LearningAssistantActivity.D;
                Intrinsics.d(bVar4);
                learningAssistantActivity.d0().d.j(ShowQuestion.None.a);
                com.quizlet.learn.viewmodel.G gB0 = learningAssistantActivity.b0();
                List answersFromPreviousRound = Collections.singletonList(bVar4.a);
                Intrinsics.checkNotNullExpressionValue(answersFromPreviousRound, "singletonList(...)");
                gB0.getClass();
                Intrinsics.checkNotNullParameter(answersFromPreviousRound, "answersFromPreviousRound");
                List questionAttributes = bVar4.b;
                Intrinsics.checkNotNullParameter(questionAttributes, "questionAttributes");
                gB0.F(answersFromPreviousRound, questionAttributes, false);
                return Unit.a;
            case 3:
                Boolean bool = (Boolean) obj;
                String str12 = LearningAssistantActivity.D;
                Intrinsics.d(bool);
                boolean zBooleanValue = bool.booleanValue();
                com.quizlet.learn.viewmodel.G gB02 = learningAssistantActivity.b0();
                gB02.getClass();
                kotlinx.coroutines.E.A(p0.j(gB02), null, null, new w(gB02, zBooleanValue, null), 3);
                return Unit.a;
            case 4:
                if (obj != null) {
                    throw new ClassCastException();
                }
                String str13 = LearningAssistantActivity.D;
                learningAssistantActivity.b0();
                throw null;
            case 5:
                com.quizlet.upgrade.util.a it2 = (com.quizlet.upgrade.util.a) obj;
                String str14 = LearningAssistantActivity.D;
                Intrinsics.checkNotNullParameter(it2, "it");
                if (it2.a) {
                    learningAssistantActivity.e0(it2.c);
                }
                return Unit.a;
            case 6:
                t tVar = (t) obj;
                String str15 = LearningAssistantActivity.D;
                learningAssistantActivity.h0(false);
                if (tVar instanceof q) {
                    learningAssistantActivity.g0(((q) tVar).a, R.string.learn_mode_mc_question_cd);
                } else if (tVar instanceof s) {
                    learningAssistantActivity.g0(((s) tVar).a, R.string.learn_mode_written_question_cd);
                } else if (tVar instanceof com.quizlet.learn.data.r) {
                    learningAssistantActivity.g0(((com.quizlet.learn.data.r) tVar).a, R.string.learn_mode_flashcard_question_cd);
                } else if (tVar instanceof C4553p) {
                    learningAssistantActivity.g0(((C4553p) tVar).a, R.string.learn_mode_fill_in_the_blank_question_cd);
                } else if (tVar instanceof C4548m) {
                    C4548m c4548m = (C4548m) tVar;
                    String str16 = LAResultsFragment.n;
                    StudyEventLogData event = c4548m.c;
                    Intrinsics.checkNotNullParameter(event, "event");
                    A1 studyModeType = c4548m.d;
                    Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
                    StudyableModelData studyableModelData2 = c4548m.e;
                    Intrinsics.checkNotNullParameter(studyableModelData2, "studyableModelData");
                    Bundle bundle3 = new Bundle();
                    bundle3.putParcelable("KEY_STUDY_EVENT_DATA", event);
                    bundle3.putDouble("KEY_STUDY_PROGRESS", c4548m.b);
                    bundle3.putInt("KEY_MODE_TYPE", studyModeType.a());
                    bundle3.putParcelable("KEY_STUDYABLE_DATA", studyableModelData2);
                    LAResultsFragment lAResultsFragment = new LAResultsFragment();
                    lAResultsFragment.setArguments(bundle3);
                    LearningAssistantActivity.f0(learningAssistantActivity, lAResultsFragment, LAResultsFragment.n, true);
                } else if (tVar instanceof C4547l) {
                    C4547l c4547l = (C4547l) tVar;
                    String str17 = LearnCheckpointFragment.o;
                    StudiableCheckpoint checkpoint = c4547l.a;
                    Intrinsics.checkNotNullParameter(checkpoint, "checkpoint");
                    StudiableTotalProgress totalProgress = c4547l.b;
                    Intrinsics.checkNotNullParameter(totalProgress, "totalProgress");
                    StudyEventLogData event2 = c4547l.c;
                    Intrinsics.checkNotNullParameter(event2, "event");
                    A1 studyModeType2 = c4547l.d;
                    Intrinsics.checkNotNullParameter(studyModeType2, "studyModeType");
                    StudyableModelData studyableModelData3 = c4547l.e;
                    Intrinsics.checkNotNullParameter(studyableModelData3, "studyableModelData");
                    String studyableTitle = c4547l.f;
                    Intrinsics.checkNotNullParameter(studyableTitle, "studyableTitle");
                    Bundle bundle4 = new Bundle();
                    bundle4.putParcelable("KEY_LEARN_CHECKPOINT_PROGRESS_DATA", totalProgress);
                    bundle4.putParcelable("KEY_LEARN_CHECKPOINT_STUDY_EVENT_DATA", event2);
                    bundle4.putParcelable("KEY_LEARN_CHECKPOINT_STUDYABLE_MDATA", studyableModelData3);
                    bundle4.putInt("KEY_LEARN_CHECKPOINT_STUDY_MODE_TYPE", studyModeType2.a());
                    bundle4.putString("KEY_LEARN_CHECKPOINT_SET_TITLE", studyableTitle);
                    LearnCheckpointFragment learnCheckpointFragment = new LearnCheckpointFragment();
                    learnCheckpointFragment.setArguments(bundle4);
                    LearningAssistantActivity.f0(learningAssistantActivity, learnCheckpointFragment, LearnCheckpointFragment.o, true);
                } else if (tVar instanceof C4546k) {
                    C4546k c4546k = (C4546k) tVar;
                    LearnRoundSummaryData learnRoundSummaryData = c4546k.a;
                    Intrinsics.checkNotNullParameter(learnRoundSummaryData, "learnRoundSummaryData");
                    LearnRoundSummaryFragment learnRoundSummaryFragment = new LearnRoundSummaryFragment();
                    learnRoundSummaryFragment.setArguments(AbstractC3206m6.a(new Pair("KEY_LEARN_ROUND_SUMMARY_DATA", learnRoundSummaryData), new Pair("KEY_LEARN_ROUND_SUMMARY_METERING_DATA", c4546k.b), new Pair("KEY_LEARN_ROUND_SUMMARY_FOCUSED_LEARN_RESULTS", Boolean.valueOf(c4546k.c))));
                    String name = LearnRoundSummaryFragment.class.getName();
                    Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
                    LearningAssistantActivity.f0(learningAssistantActivity, learnRoundSummaryFragment, name, true);
                } else if (tVar instanceof C4549n) {
                    C4549n c4549n = (C4549n) tVar;
                    String str18 = LearnEndingFragment.m;
                    StudyableModelData studyableModelData4 = c4549n.a;
                    Intrinsics.checkNotNullParameter(studyableModelData4, "studyableModelData");
                    AssistantCheckpointProgressState progressState = c4549n.d;
                    Intrinsics.checkNotNullParameter(progressState, "progressState");
                    LearnEndingFragment learnEndingFragment = new LearnEndingFragment();
                    learnEndingFragment.setArguments(AbstractC3206m6.a(new Pair("STUDYABLE_MODEL_DATA_KEY", studyableModelData4), new Pair("CURRENT_TASK_PROGRESS_KEY", c4549n.b), new Pair("METERING_DATA_KEY", c4549n.c), new Pair("ASSISTANT_CHECKPOINT_PROGRESS_STATE", progressState)));
                    LearningAssistantActivity.f0(learningAssistantActivity, learnEndingFragment, LearnEndingFragment.m, true);
                    LottieAnimationView lottieAnimationView = ((C4609m) learningAssistantActivity.K()).b;
                    lottieAnimationView.n.add(EnumC1466f.f);
                    lottieAnimationView.h.k();
                } else if (tVar instanceof C4545j) {
                    C4545j c4545j = (C4545j) tVar;
                    com.quizlet.quizletandroid.ui.learnpaywall.k kVar = (com.quizlet.quizletandroid.ui.learnpaywall.k) learningAssistantActivity.x.getValue();
                    long j = c4545j.a;
                    StudiableMeteringData studiableMeteringData = c4545j.c;
                    if (studiableMeteringData == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    kVar.C(j, c4545j.b, studiableMeteringData, false);
                    LearningAssistantActivity.f0(learningAssistantActivity, new LearnPaywallFragment(), LearnPaywallFragment.h, true);
                } else {
                    if (!(tVar instanceof C4544i)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    learningAssistantActivity.setResult(115);
                    learningAssistantActivity.finish();
                }
                return Unit.a;
            default:
                LearnSettingsResult it3 = (LearnSettingsResult) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                String str19 = LearningAssistantActivity.D;
                learningAssistantActivity.b0().W(it3);
                ((ComposeView) learningAssistantActivity.s.getValue()).setVisibility(8);
                return Unit.a;
        }
    }
}
