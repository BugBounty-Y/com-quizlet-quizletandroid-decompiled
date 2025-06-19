package com.quizlet.quizletandroid.ui.studymodes.match.fragment;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C;
import com.quizlet.quizletandroid.ui.common.ads.E;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class MatchStartGameFragment extends Hilt_MatchStartGameFragment<C> {
    public static final String n;
    public E j;
    public com.quizlet.quizletandroid.ui.common.ads.prebid.m k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e l = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g.class), new o(this, 0), new o(this, 2), new o(this, 1));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e m;

    static {
        Intrinsics.checkNotNullExpressionValue("MatchStartGameFragment", "getSimpleName(...)");
        n = "MatchStartGameFragment";
    }

    public MatchStartGameFragment() {
        com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a aVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 3);
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new o(this, 3), 29));
        this.m = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.match.viewmodel.h.class), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 7), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 23), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(aVar, kVarA, 22));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return n;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_match_start, viewGroup, false);
        int i = R.id.floating_ad_container;
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.floating_ad_container, viewInflate);
        if (frameLayout != null) {
            i = R.id.match_game_description;
            if (((QTextView) AbstractC3375o2.c(R.id.match_game_description, viewInflate)) != null) {
                i = R.id.matchOgLayout;
                if (((ConstraintLayout) AbstractC3375o2.c(R.id.matchOgLayout, viewInflate)) != null) {
                    i = R.id.match_ready_text;
                    if (((QTextView) AbstractC3375o2.c(R.id.match_ready_text, viewInflate)) != null) {
                        ConstraintLayout constraintLayout = (ConstraintLayout) viewInflate;
                        int i2 = R.id.match_start_game;
                        QButton qButton = (QButton) AbstractC3375o2.c(R.id.match_start_game, viewInflate);
                        if (qButton != null) {
                            i2 = R.id.match_start_other_mode;
                            QButton qButton2 = (QButton) AbstractC3375o2.c(R.id.match_start_other_mode, viewInflate);
                            if (qButton2 != null) {
                                C c = new C(constraintLayout, frameLayout, qButton, qButton2);
                                Intrinsics.checkNotNullExpressionValue(c, "inflate(...)");
                                return c;
                            }
                        }
                        i = i2;
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g T() {
        return (com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g) this.l.getValue();
    }

    public final QButton U() {
        QButton matchStartGame = ((C) J()).c;
        Intrinsics.checkNotNullExpressionValue(matchStartGame, "matchStartGame");
        return matchStartGame;
    }

    public final QButton V() {
        QButton matchStartOtherMode = ((C) J()).d;
        Intrinsics.checkNotNullExpressionValue(matchStartOtherMode, "matchStartOtherMode");
        return matchStartOtherMode;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        ((com.quizlet.features.match.viewmodel.h) this.m.getValue()).c.m(this, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, this, MatchStartGameFragment.class, "onLoading", "onLoading()V", 0, 16), new y(1, this, MatchStartGameFragment.class, "onRender", "onRender(Lcom/quizlet/features/match/data/MatchStartViewState;)V", 0, 10));
        T().w.f(this, new com.quizlet.ads.ui.fragments.c(new y(1, this, MatchStartGameFragment.class, "setupAd", "setupAd(Z)V", 0, 11)));
    }
}
