package com.quizlet.quizletandroid.ui.studymodes.match.fragment;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class MatchGameFragment extends Hilt_MatchGameFragment<com.quizlet.features.questiontypes.databinding.a> {
    public static final String m;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g.class), new k(this, 0), new k(this, 2), new k(this, 1));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e k;
    public final kotlin.u l;

    static {
        Intrinsics.checkNotNullExpressionValue("MatchGameFragment", "getSimpleName(...)");
        m = "MatchGameFragment";
    }

    public MatchGameFragment() {
        j jVar = new j(this, 0);
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new k(this, 3), 28));
        this.k = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.match.viewmodel.f.class), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 6), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 21), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(jVar, kVarA, 20));
        this.l = kotlin.l.b(new j(this, 1));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return m;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_match_game, viewGroup, false);
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.gameContainer, viewInflate);
        if (frameLayout == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.gameContainer)));
        }
        com.quizlet.features.questiontypes.databinding.a aVar = new com.quizlet.features.questiontypes.databinding.a((ConstraintLayout) viewInflate, frameLayout, 1);
        Intrinsics.checkNotNullExpressionValue(aVar, "inflate(...)");
        return aVar;
    }

    public final com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g T() {
        return (com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g) this.j.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.k;
        ((com.quizlet.features.match.viewmodel.f) eVar.getValue()).d.m(this, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, this, MatchGameFragment.class, "onLoading", "onLoading()V", 0, 15), new y(1, this, MatchGameFragment.class, "onRender", "onRender(Lcom/quizlet/features/match/data/MatchGameManagerState;)V", 0, 9));
        ((com.quizlet.features.match.viewmodel.f) eVar.getValue()).e.f(this, new com.quizlet.ads.ui.fragments.c(this, 18));
        com.quizlet.features.match.viewmodel.f fVar = (com.quizlet.features.match.viewmodel.f) eVar.getValue();
        boolean zBooleanValue = ((Boolean) this.l.getValue()).booleanValue();
        if (fVar.f) {
            return;
        }
        com.quizlet.features.match.studyengine.e eVar2 = (com.quizlet.features.match.studyengine.e) fVar.c;
        com.quizlet.features.match.studyengine.b bVar = eVar2.a;
        com.quizlet.data.repository.metering.j jVar = bVar.a;
        io.reactivex.rxjava3.internal.operators.single.g gVarG = ((io.reactivex.rxjava3.subjects.r) jVar.d).g(new com.quizlet.features.match.game.a(zBooleanValue, jVar));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        io.reactivex.rxjava3.internal.operators.single.d dVar = new io.reactivex.rxjava3.internal.operators.single.d(gVarG.g(new com.google.firebase.crashlytics.internal.common.j(bVar, 17)), new com.quizlet.analytics.marketing.e(bVar, 7), 2);
        Intrinsics.checkNotNullExpressionValue(dVar, "doOnSuccess(...)");
        io.reactivex.rxjava3.internal.operators.single.g gVarG2 = new io.reactivex.rxjava3.internal.operators.single.d(dVar, new com.quizlet.analytics.marketing.e(eVar2, 8), 2).g(com.quizlet.features.match.studyengine.d.a);
        Intrinsics.checkNotNullExpressionValue(gVarG2, "map(...)");
        io.reactivex.rxjava3.internal.observers.e eVarI = new io.reactivex.rxjava3.internal.operators.single.d(gVarG2, new com.quizlet.features.match.viewmodel.e(fVar, 0), 2).i(new com.quizlet.features.match.viewmodel.e(fVar, 1), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarI, "<this>");
        fVar.A(eVarI);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onPause() {
        super.onPause();
        ((com.quizlet.features.match.viewmodel.f) this.k.getValue()).g = true;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() {
        super.onResume();
        com.quizlet.features.match.viewmodel.f fVar = (com.quizlet.features.match.viewmodel.f) this.k.getValue();
        if (fVar.g) {
            com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) fVar.c;
            fVar.e.l(new com.quizlet.features.match.data.r(eVar.f, eVar.h));
            fVar.g = false;
        }
    }
}
