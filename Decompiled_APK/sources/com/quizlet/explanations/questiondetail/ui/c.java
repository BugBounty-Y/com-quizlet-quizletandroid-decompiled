package com.quizlet.explanations.questiondetail.ui;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.data.model.Question;
import com.quizlet.data.model.X;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ QuestionDetailFragment b;

    public /* synthetic */ c(QuestionDetailFragment questionDetailFragment, int i) {
        this.a = i;
        this.b = questionDetailFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        X x;
        QuestionDetailFragment questionDetailFragment = this.b;
        switch (this.a) {
            case 0:
                String str = QuestionDetailFragment.v;
                com.quizlet.explanations.navigation.b bVarU = questionDetailFragment.U();
                Context contextRequireContext = questionDetailFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                ((com.quizlet.quizletandroid.ui.navigationmanagers.b) bVarU).b(contextRequireContext, questionDetailFragment.V());
                return Unit.a;
            case 1:
                String str2 = QuestionDetailFragment.v;
                com.quizlet.explanations.navigation.b bVarU2 = questionDetailFragment.U();
                Context contextRequireContext2 = questionDetailFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                ((com.quizlet.quizletandroid.ui.navigationmanagers.b) bVarU2).a(contextRequireContext2, questionDetailFragment.V());
                return Unit.a;
            case 2:
                if (questionDetailFragment.j != null) {
                    return new com.quizlet.explanations.questiondetail.recyclerview.d(AbstractC4178x.h("diffUtilCallback"));
                }
                Intrinsics.m("headerAdapterFactory");
                throw null;
            case 3:
                if (questionDetailFragment.k != null) {
                    return new com.quizlet.explanations.solution.solutionwall.a(AbstractC4178x.h("diffUtilCallback"));
                }
                Intrinsics.m("explanationsSolutionWallAdapterFactory");
                throw null;
            case 4:
                if (questionDetailFragment.l != null) {
                    return new com.quizlet.explanations.questiondetail.recyclerview.a(AbstractC4178x.h("diffUtilCallback"));
                }
                Intrinsics.m("extraInfoAdapterFactory");
                throw null;
            case 5:
                String str3 = QuestionDetailFragment.v;
                questionDetailFragment.getClass();
                Intrinsics.checkNotNullParameter("explanations_paywall_upsell", "source");
                com.quizlet.explanations.questiondetail.viewmodel.f fVarW = questionDetailFragment.W();
                Question question = fVarW.A;
                if (question != null && (x = fVarW.B) != null) {
                    ExplanationsLogger.EventData.Metering eventData = new ExplanationsLogger.EventData.Metering(question.c, 16, x.d, x.b);
                    ExplanationsLogger.MeteringPlacement placement = ExplanationsLogger.MeteringPlacement.a;
                    ExplanationsLogger explanationsLogger = fVarW.g;
                    explanationsLogger.getClass();
                    Intrinsics.checkNotNullParameter(eventData, "eventData");
                    Intrinsics.checkNotNullParameter(placement, "placement");
                    ExplanationsEventLog.Companion companion = ExplanationsEventLog.b;
                    com.quizlet.eventlogger.features.explanations.d dVar = new com.quizlet.eventlogger.features.explanations.d(explanationsLogger, eventData, placement, 0);
                    companion.getClass();
                    explanationsLogger.a(ExplanationsEventLog.Companion.a("metered_explanations_paywall_cta_click", dVar));
                }
                questionDetailFragment.U();
                Context context = questionDetailFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                com.quizlet.features.infra.models.upgrade.a upgradeNavigationSource = com.quizlet.features.infra.models.upgrade.a.n;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter("explanations_paywall_upsell", "source");
                Intrinsics.checkNotNullParameter(upgradeNavigationSource, "upgradeNavigationSource");
                String str4 = UpgradeActivity.v;
                Intent intentI = AbstractC3242q6.i(context, "explanations_paywall_upsell", upgradeNavigationSource);
                androidx.activity.result.b bVar = questionDetailFragment.u;
                if (bVar != null) {
                    bVar.a(intentI);
                    return Unit.a;
                }
                Intrinsics.m("upgradeResultLauncher");
                throw null;
            default:
                String str5 = QuestionDetailFragment.v;
                questionDetailFragment.X(com.quizlet.explanations.questiondetail.data.f.a);
                return Unit.a;
        }
    }
}
