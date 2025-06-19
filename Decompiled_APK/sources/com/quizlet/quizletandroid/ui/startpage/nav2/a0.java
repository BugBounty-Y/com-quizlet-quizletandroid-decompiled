package com.quizlet.quizletandroid.ui.startpage.nav2;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_document_scanner.S5;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.joincontenttofolder.JoinContentToFolderActivity;
import com.quizlet.quizletandroid.ui.setpage.addset.AddSetToClassActivity;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4741j;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4742k;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4745n;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.OnDismissFragment;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a0 implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ RecommendationsActionOptionsFragment b;

    public /* synthetic */ a0(RecommendationsActionOptionsFragment recommendationsActionOptionsFragment, int i) {
        this.a = i;
        this.b = recommendationsActionOptionsFragment;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        RecommendationsActionOptionsFragment recommendationsActionOptionsFragment = this.b;
        switch (this.a) {
            case 0:
                com.quizlet.features.setpage.managers.a aVar = (com.quizlet.features.setpage.managers.a) obj;
                String str = RecommendationsActionOptionsFragment.D;
                Intrinsics.checkNotNullParameter(aVar, "<destruct>");
                int i = aVar.a;
                com.quizlet.features.infra.snackbar.c cVar = com.quizlet.features.infra.snackbar.k.a;
                Object[] args = {Integer.valueOf(i)};
                Intrinsics.checkNotNullParameter(args, "args");
                com.quizlet.qutils.string.d dVar = new com.quizlet.qutils.string.d(R.plurals.sets_added_to_class_message, i, C4933y.P(args));
                Object[] args2 = new Object[0];
                Intrinsics.checkNotNullParameter(args2, "args");
                com.quizlet.features.infra.snackbar.l lVar = new com.quizlet.features.infra.snackbar.l(cVar, 0, dVar, new com.quizlet.qutils.string.f(R.string.undo, C4933y.P(args2)), aVar.b, 40);
                com.quizlet.features.infra.snackbar.viewmodel.a aVar2 = recommendationsActionOptionsFragment.C;
                if (aVar2 != null) {
                    ((com.quizlet.features.infra.snackbar.viewmodel.c) aVar2).A(lVar);
                    return Unit.a;
                }
                Intrinsics.m("snackbarViewModel");
                throw null;
            default:
                com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.M m = (com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.M) obj;
                String str2 = RecommendationsActionOptionsFragment.D;
                if (m instanceof C4741j) {
                    long j = ((C4741j) m).a;
                    String str3 = AddSetToClassActivity.s;
                    Context contextRequireContext = recommendationsActionOptionsFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                    recommendationsActionOptionsFragment.startActivityForResult(S5.b(contextRequireContext, kotlin.collections.A.b(Long.valueOf(j))), 216);
                } else if (m instanceof C4742k) {
                    long j2 = ((C4742k) m).a;
                    String str4 = JoinContentToFolderActivity.r;
                    Context context = recommendationsActionOptionsFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                    List setIds = kotlin.collections.A.b(Long.valueOf(j2));
                    Intrinsics.checkNotNullParameter(context, "context");
                    Intrinsics.checkNotNullParameter(setIds, "setIds");
                    Intent intent = new Intent(context, (Class<?>) JoinContentToFolderActivity.class);
                    intent.putExtra("setIds", CollectionsKt.x0(setIds));
                    recommendationsActionOptionsFragment.startActivityForResult(intent, 222);
                } else if (m instanceof C4745n) {
                    C4745n c4745n = (C4745n) m;
                    long j3 = c4745n.a;
                    recommendationsActionOptionsFragment.H(false, false);
                    String str5 = HideRecommendationFeedbackFragment.B;
                    Bundle bundle = new Bundle();
                    bundle.putLong("setID", j3);
                    Integer num = c4745n.b;
                    if (num != null) {
                        bundle.putInt("recsSectionNumber", num.intValue());
                    }
                    HideRecommendationFeedbackFragment hideRecommendationFeedbackFragment = new HideRecommendationFeedbackFragment();
                    hideRecommendationFeedbackFragment.setArguments(bundle);
                    hideRecommendationFeedbackFragment.O(recommendationsActionOptionsFragment.getParentFragmentManager(), HideRecommendationFeedbackFragment.B);
                } else {
                    if (!Intrinsics.b(m, OnDismissFragment.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    recommendationsActionOptionsFragment.H(false, false);
                }
                return Unit.a;
        }
    }
}
