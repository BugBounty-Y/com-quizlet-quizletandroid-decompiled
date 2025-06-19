package com.quizlet.features.achievements.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.UI.fragment.C4062f;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;
import kotlin.u;

@Metadata
/* loaded from: classes2.dex */
public final class AchievementsFragment extends Hilt_AchievementsFragment<com.quizlet.features.achievements.databinding.a> {
    public static final String l;
    public final u j = l.b(new c(this, 0));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e k;

    static {
        Intrinsics.checkNotNullExpressionValue("AchievementsFragment", "getSimpleName(...)");
        l = "AchievementsFragment";
    }

    public AchievementsFragment() {
        c cVar = new c(this, 1);
        k kVarA = l.a(m.c, new assistantMode.experiments.a(new assistantMode.experiments.a(this, 23), 24));
        this.k = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.achievements.viewmodel.b.class), new C4062f(kVarA, 26), new androidx.credentials.playservices.controllers.BeginSignIn.d(24, this, kVarA), new androidx.credentials.playservices.controllers.BeginSignIn.d(23, cVar, kVarA));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return l;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_achievements, viewGroup, false);
        RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.recyclerView, viewInflate);
        if (recyclerView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.recyclerView)));
        }
        com.quizlet.features.achievements.databinding.a aVar = new com.quizlet.features.achievements.databinding.a((ConstraintLayout) viewInflate, recyclerView);
        Intrinsics.checkNotNullExpressionValue(aVar, "inflate(...)");
        return aVar;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        RecyclerView recyclerView = ((com.quizlet.features.achievements.databinding.a) J()).b;
        Intrinsics.checkNotNullExpressionValue(recyclerView, "recyclerView");
        recyclerView.setAdapter(null);
        super.onDestroyView();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        RecyclerView recyclerView = ((com.quizlet.features.achievements.databinding.a) J()).b;
        Intrinsics.checkNotNullExpressionValue(recyclerView, "recyclerView");
        recyclerView.setAdapter((com.quizlet.baseui.compose.b) this.j.getValue());
        recyclerView.setLayoutManager(new LinearLayoutManager(recyclerView.getContext()));
    }
}
