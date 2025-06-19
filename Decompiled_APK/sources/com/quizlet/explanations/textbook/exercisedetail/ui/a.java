package com.quizlet.explanations.textbook.exercisedetail.ui;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.data.model.ExerciseDetails;
import com.quizlet.data.model.X;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ExerciseDetailFragment b;

    public /* synthetic */ a(ExerciseDetailFragment exerciseDetailFragment, int i) {
        this.a = i;
        this.b = exerciseDetailFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        X x;
        ExerciseDetailFragment exerciseDetailFragment = this.b;
        switch (this.a) {
            case 0:
                String str = ExerciseDetailFragment.y;
                exerciseDetailFragment.getClass();
                Intrinsics.checkNotNullParameter("explanations_paywall_upsell", "source");
                com.quizlet.explanations.textbook.exercisedetail.viewmodel.c cVarV = exerciseDetailFragment.V();
                ExerciseDetails exerciseDetails = cVarV.t;
                if (exerciseDetails != null && (x = cVarV.u) != null) {
                    ExplanationsLogger.EventData.Metering eventData = new ExplanationsLogger.EventData.Metering(exerciseDetails.b, 15, x.d, x.b);
                    ExplanationsLogger.MeteringPlacement placement = ExplanationsLogger.MeteringPlacement.b;
                    ExplanationsLogger explanationsLogger = cVarV.e;
                    explanationsLogger.getClass();
                    Intrinsics.checkNotNullParameter(eventData, "eventData");
                    Intrinsics.checkNotNullParameter(placement, "placement");
                    ExplanationsEventLog.Companion companion = ExplanationsEventLog.b;
                    com.quizlet.eventlogger.features.explanations.d dVar = new com.quizlet.eventlogger.features.explanations.d(explanationsLogger, eventData, placement, 0);
                    companion.getClass();
                    explanationsLogger.a(ExplanationsEventLog.Companion.a("metered_explanations_paywall_cta_click", dVar));
                }
                if (exerciseDetailFragment.n == null) {
                    Intrinsics.m("navigationManager");
                    throw null;
                }
                Context context = exerciseDetailFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                com.quizlet.features.infra.models.upgrade.a upgradeNavigationSource = com.quizlet.features.infra.models.upgrade.a.n;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter("explanations_paywall_upsell", "source");
                Intrinsics.checkNotNullParameter(upgradeNavigationSource, "upgradeNavigationSource");
                String str2 = UpgradeActivity.v;
                Intent intentI = AbstractC3242q6.i(context, "explanations_paywall_upsell", upgradeNavigationSource);
                androidx.activity.result.b bVar = exerciseDetailFragment.x;
                if (bVar != null) {
                    bVar.a(intentI);
                    return Unit.a;
                }
                Intrinsics.m("upgradeResultLauncher");
                throw null;
            case 1:
                String str3 = ExerciseDetailFragment.y;
                com.quizlet.explanations.navigation.b bVar2 = exerciseDetailFragment.n;
                if (bVar2 == null) {
                    Intrinsics.m("navigationManager");
                    throw null;
                }
                com.quizlet.ui.models.webpage.c webPage = com.quizlet.ui.models.webpage.c.c;
                Intrinsics.checkNotNullParameter(webPage, "webPage");
                com.quizlet.quizletandroid.ui.webpages.a.a.c(((com.quizlet.quizletandroid.ui.navigationmanagers.b) bVar2).a, webPage);
                return Unit.a;
            case 2:
                if (exerciseDetailFragment.j != null) {
                    return new com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.e(AbstractC4178x.h("diffUtilCallback"));
                }
                Intrinsics.m("headerAdapterFactory");
                throw null;
            case 3:
                com.google.firebase.crashlytics.internal.settings.b bVar3 = exerciseDetailFragment.k;
                if (bVar3 != null) {
                    return new com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.a((com.quizlet.qutils.image.loading.a) bVar3.b);
                }
                Intrinsics.m("extraInfoAdapterFactory");
                throw null;
            case 4:
                if (exerciseDetailFragment.l != null) {
                    return new com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.c(AbstractC4178x.h("diffUtilCallback"));
                }
                Intrinsics.m("footerAdapterFactory");
                throw null;
            case 5:
                if (exerciseDetailFragment.m != null) {
                    return new com.quizlet.explanations.solution.solutionwall.a(AbstractC4178x.h("diffUtilCallback"));
                }
                Intrinsics.m("explanationsSolutionWallAdapterFactory");
                throw null;
            case 6:
                String str4 = ExerciseDetailFragment.y;
                com.quizlet.explanations.navigation.b bVar4 = exerciseDetailFragment.n;
                if (bVar4 == null) {
                    Intrinsics.m("navigationManager");
                    throw null;
                }
                Context contextRequireContext = exerciseDetailFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                ((com.quizlet.quizletandroid.ui.navigationmanagers.b) bVar4).b(contextRequireContext, exerciseDetailFragment.U());
                return Unit.a;
            default:
                String str5 = ExerciseDetailFragment.y;
                com.quizlet.explanations.navigation.b bVar5 = exerciseDetailFragment.n;
                if (bVar5 == null) {
                    Intrinsics.m("navigationManager");
                    throw null;
                }
                Context contextRequireContext2 = exerciseDetailFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                ((com.quizlet.quizletandroid.ui.navigationmanagers.b) bVar5).a(contextRequireContext2, exerciseDetailFragment.U());
                return Unit.a;
        }
    }
}
