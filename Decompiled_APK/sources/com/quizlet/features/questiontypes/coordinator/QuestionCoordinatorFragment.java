package com.quizlet.features.questiontypes.coordinator;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.ads.ui.fragments.c;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.G;
import com.quizlet.features.questiontypes.basequestion.i;
import com.quizlet.features.questiontypes.basequestion.k;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class QuestionCoordinatorFragment extends Hilt_QuestionCoordinatorFragment<com.quizlet.features.questiontypes.databinding.a> {
    public static final String k;
    public final e j = new e(K.a(k.class), new a(this, 0), new a(this, 2), new a(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("QuestionCoordinatorFragment", "getSimpleName(...)");
        k = "QuestionCoordinatorFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return k;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_question_coordinator, viewGroup, false);
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.fragmentContainer, viewInflate);
        if (frameLayout == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.fragmentContainer)));
        }
        com.quizlet.features.questiontypes.databinding.a aVar = new com.quizlet.features.questiontypes.databinding.a((ConstraintLayout) viewInflate, frameLayout, 0);
        Intrinsics.checkNotNullExpressionValue(aVar, "inflate(...)");
        return aVar;
    }

    public final void T(BaseFragment baseFragment, String str) {
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        childFragmentManager.getClass();
        C1121a c1121a = new C1121a(childFragmentManager);
        c1121a.m(0, 0);
        c1121a.l(R.id.fragmentContainer, baseFragment, str);
        c1121a.g();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        ((k) ((i) this.j.getValue())).d.f(getViewLifecycleOwner(), new c(new G(1, this, QuestionCoordinatorFragment.class, "showQuestion", "showQuestion(Lcom/quizlet/features/questiontypes/basequestion/data/ShowQuestion;)V", 0, 21)));
    }
}
