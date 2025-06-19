package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import android.view.LayoutInflater;
import android.view.ViewGroup;
import com.quizlet.learn.viewmodel.G;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class LearnRoundSummaryFragment extends Hilt_LearnRoundSummaryFragment<androidx.viewbinding.a> {
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(G.class), new q(this, 0), new q(this, 2), new q(this, 1));

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return LearnRoundSummaryFragment.class.getName();
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 27);
    }
}
