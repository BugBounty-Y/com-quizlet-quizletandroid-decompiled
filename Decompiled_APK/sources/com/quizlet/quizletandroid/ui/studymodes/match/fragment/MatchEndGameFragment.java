package com.quizlet.quizletandroid.ui.studymodes.match.fragment;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import androidx.work.impl.model.v;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.measurement.internal.N;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.features.match.data.F;
import com.quizlet.features.match.data.W;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QProgressBar;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.B;
import com.quizlet.quizletandroid.ui.common.views.ShareSetButton;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class MatchEndGameFragment extends Hilt_MatchEndGameFragment<B> {
    public static final String p;
    public com.quizlet.quizletandroid.util.f j;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e k = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g.class), new h(this, 0), new h(this, 2), new h(this, 1));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e l;
    public final kotlin.u m;
    public final kotlin.u n;
    public final kotlin.u o;

    static {
        Intrinsics.checkNotNullExpressionValue("MatchEndGameFragment", "getSimpleName(...)");
        p = "MatchEndGameFragment";
    }

    public MatchEndGameFragment() {
        g gVar = new g(this, 0);
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new h(this, 3), 27));
        this.l = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a.class), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 5), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 19), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(gVar, kVarA, 18));
        this.m = kotlin.l.b(new g(this, 1));
        this.n = kotlin.l.b(new g(this, 2));
        this.o = kotlin.l.b(new g(this, 3));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return p;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_match_results, viewGroup, false);
        int i = R.id.match_error;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.match_error, viewInflate);
        if (qTextView != null) {
            i = R.id.match_finish_seconds;
            QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.match_finish_seconds, viewInflate);
            if (qTextView2 != null) {
                i = R.id.match_finish_text;
                QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.match_finish_text, viewInflate);
                if (qTextView3 != null) {
                    i = R.id.match_leaderboard_score;
                    RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.match_leaderboard_score, viewInflate);
                    if (recyclerView != null) {
                        View viewC = AbstractC3375o2.c(R.id.match_margin_view, viewInflate);
                        i = R.id.match_personal_record;
                        QTextView qTextView4 = (QTextView) AbstractC3375o2.c(R.id.match_personal_record, viewInflate);
                        if (qTextView4 != null) {
                            i = R.id.match_play_again;
                            QButton qButton = (QButton) AbstractC3375o2.c(R.id.match_play_again, viewInflate);
                            if (qButton != null) {
                                i = R.id.match_play_other_selected_terms_mode;
                                QButton qButton2 = (QButton) AbstractC3375o2.c(R.id.match_play_other_selected_terms_mode, viewInflate);
                                if (qButton2 != null) {
                                    i = R.id.match_progress_bar;
                                    QProgressBar qProgressBar = (QProgressBar) AbstractC3375o2.c(R.id.match_progress_bar, viewInflate);
                                    if (qProgressBar != null) {
                                        i = R.id.match_share_set_button;
                                        ShareSetButton shareSetButton = (ShareSetButton) AbstractC3375o2.c(R.id.match_share_set_button, viewInflate);
                                        if (shareSetButton != null) {
                                            B b = new B(viewInflate, viewInflate, qTextView, qTextView2, qTextView3, recyclerView, viewC, qTextView4, qButton, qButton2, qProgressBar, shareSetButton);
                                            Intrinsics.checkNotNullExpressionValue(b, "inflate(...)");
                                            return b;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final RecyclerView T() {
        RecyclerView matchLeaderboardScore = ((B) J()).f;
        Intrinsics.checkNotNullExpressionValue(matchLeaderboardScore, "matchLeaderboardScore");
        return matchLeaderboardScore;
    }

    public final com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a U() {
        return (com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a) this.l.getValue();
    }

    public final com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g V() {
        return (com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g) this.k.getValue();
    }

    public final QButton W() {
        QButton matchPlayAgain = ((B) J()).i;
        Intrinsics.checkNotNullExpressionValue(matchPlayAgain, "matchPlayAgain");
        return matchPlayAgain;
    }

    public final QButton X() {
        QButton matchPlayOtherSelectedTermsMode = ((B) J()).j;
        Intrinsics.checkNotNullExpressionValue(matchPlayOtherSelectedTermsMode, "matchPlayOtherSelectedTermsMode");
        return matchPlayOtherSelectedTermsMode;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        io.reactivex.rxjava3.core.p pVarD;
        super.onCreate(bundle);
        com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a aVarU = U();
        long jLongValue = ((Number) this.m.getValue()).longValue();
        long jLongValue2 = ((Number) this.n.getValue()).longValue();
        long jLongValue3 = ((Number) this.o.getValue()).longValue();
        if (!aVarU.p) {
            com.google.android.datatransport.cct.internal.s sVar = aVarU.i;
            DBSession dBSessionB = ((com.quizlet.features.infra.basestudy.manager.f) sVar.c).b();
            dBSessionB.setEndedTimestampMs(jLongValue);
            long j = (jLongValue2 + jLongValue3) / 100;
            dBSessionB.setScore(j);
            ((com.quizlet.infra.legacysyncengine.managers.i) sVar.e).c(dBSessionB);
            UserInfoCache userInfoCache = (UserInfoCache) sVar.d;
            com.quizlet.features.match.highscore.a aVar = new com.quizlet.features.match.highscore.a(userInfoCache.getUsername(), j, userInfoCache.getProfileImage(), -1, userInfoCache.getPersonId(), dBSessionB.getEndedTimestampMs(), true);
            io.reactivex.rxjava3.internal.operators.single.d s1 = new io.reactivex.rxjava3.internal.operators.single.d(sVar.m(j), new com.quizlet.features.match.game.b(aVarU.q, 4), 2);
            Intrinsics.checkNotNullExpressionValue(s1, "doOnSuccess(...)");
            com.quizlet.data.repository.metering.j jVar = aVarU.h;
            jVar.getClass();
            io.reactivex.rxjava3.internal.operators.single.g gVarG = ((io.reactivex.rxjava3.subjects.r) jVar.d).g(new com.quizlet.data.interactor.course.a(jVar, 12));
            Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
            io.reactivex.rxjava3.internal.operators.single.g s2 = gVarG.g(new com.quizlet.quizletandroid.ui.activitycenter.models.a());
            Intrinsics.checkNotNullExpressionValue(s2, "map(...)");
            com.quizlet.quizletandroid.ui.studymodes.match.managers.a aVar2 = aVarU.j;
            com.quizlet.features.infra.basestudy.manager.f fVar = aVar2.a;
            DBStudySet dBStudySetE = fVar.e();
            io.reactivex.rxjava3.core.p s3 = dBStudySetE != null ? fVar.f().g(new v(28, aVar2, dBStudySetE)) : io.reactivex.rxjava3.core.p.f(new W(com.quizlet.features.infra.basestudy.data.models.shareset.a.d, null, aVar2.b.e.getPersonId()));
            Intrinsics.checkNotNullParameter(s1, "s1");
            Intrinsics.checkNotNullParameter(s2, "s2");
            Intrinsics.checkNotNullParameter(s3, "s3");
            io.reactivex.rxjava3.core.p pVarO = io.reactivex.rxjava3.core.p.o(s1, s2, s3, io.reactivex.rxjava3.kotlin.a.e);
            Intrinsics.checkNotNullExpressionValue(pVarO, "Single.zip(s1, s2, s3, F… -> Triple(t1, t2, t3) })");
            io.reactivex.rxjava3.internal.observers.e eVarI = pVarO.g(new com.quizlet.data.repository.activitycenter.b(28, aVarU, aVar)).i(new com.quizlet.quizletandroid.ui.setpage.terms.c(aVarU.k, 6), io.reactivex.rxjava3.internal.functions.d.e);
            Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
            Intrinsics.checkNotNullParameter(eVarI, "<this>");
            aVarU.A(eVarI);
            N n = (N) sVar.b;
            if (n.a <= 0 || n.b) {
                aVarU.l.o(F.a);
            } else {
                IQuizletApiClient apiClient = (IQuizletApiClient) sVar.g;
                Intrinsics.checkNotNullParameter(apiClient, "apiClient");
                io.reactivex.rxjava3.core.o networkScheduler = (io.reactivex.rxjava3.core.o) sVar.h;
                Intrinsics.checkNotNullParameter(networkScheduler, "networkScheduler");
                if (n.a <= 0 || n.b) {
                    pVarD = io.reactivex.rxjava3.core.p.d(new IllegalStateException("Studyable does not qualify"));
                    Intrinsics.checkNotNullExpressionValue(pVarD, "error(...)");
                } else {
                    pVarD = new io.reactivex.rxjava3.internal.operators.single.b(apiClient.x(n.c, (G1) n.e, (A1) n.d).l(networkScheduler).g(new com.google.firebase.crashlytics.internal.settings.b(n, 20)).g(new com.quizlet.data.interactor.achievements.f(n, 16)));
                    Intrinsics.checkNotNullExpressionValue(pVarD, "cache(...)");
                }
                io.reactivex.rxjava3.internal.operators.single.g gVarG2 = pVarD.g(new com.quizlet.quizletandroid.ui.login.h(aVar, 5));
                TimeUnit timeUnit = TimeUnit.SECONDS;
                io.reactivex.rxjava3.core.o oVar = io.reactivex.rxjava3.schedulers.e.b;
                Objects.requireNonNull(timeUnit, "unit is null");
                Objects.requireNonNull(oVar, "scheduler is null");
                io.reactivex.rxjava3.internal.observers.e eVarI2 = new io.reactivex.rxjava3.internal.operators.single.m(gVarG2, 5L, oVar, null).i(new com.quizlet.billing.manager.b(20, aVarU, aVar), new com.quizlet.quizletandroid.ui.setpage.terms.c(aVarU, 5));
                Intrinsics.checkNotNullExpressionValue(eVarI2, "subscribe(...)");
                Intrinsics.checkNotNullParameter(eVarI2, "<this>");
                aVarU.A(eVarI2);
            }
            aVarU.p = true;
        }
        U().k.m(this, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, this, MatchEndGameFragment.class, "onViewStateLoading", "onViewStateLoading()V", 0, 13), new y(1, this, MatchEndGameFragment.class, "onViewStateRender", "onViewStateRender(Lcom/quizlet/features/match/data/MatchEndViewState;)V", 0, 5));
        U().l.m(this, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, this, MatchEndGameFragment.class, "onHighScoreStateLoading", "onHighScoreStateLoading()V", 0, 14), new y(1, this, MatchEndGameFragment.class, "onHighScoreStateRender", "onHighScoreStateRender(Lcom/quizlet/features/match/data/MatchHighScoresViewState;)V", 0, 6));
        U().m.f(this, new com.quizlet.ads.ui.activity.a(3, new y(1, V(), com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g.class, "onUpdateShareTooltipState", "onUpdateShareTooltipState(Lcom/quizlet/features/match/data/ShareTooltipState;)V", 0, 7)));
        U().n.f(this, new com.quizlet.ads.ui.activity.a(3, new y(1, this, MatchEndGameFragment.class, "showChallengeDialog", "showChallengeDialog(Lcom/quizlet/features/match/data/ShowChallengeEvent;)V", 0, 8)));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        T().setAdapter(null);
        super.onDestroyView();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        com.quizlet.features.infra.basestudy.manager.f.k(U().g.a, "results", null, 6);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStop() {
        super.onStop();
        U().g.a.l("results");
    }
}
