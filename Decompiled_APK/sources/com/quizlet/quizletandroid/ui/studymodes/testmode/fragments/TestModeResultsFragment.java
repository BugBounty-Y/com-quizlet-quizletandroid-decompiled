package com.quizlet.quizletandroid.ui.studymodes.testmode.fragments;

import android.view.LayoutInflater;
import android.view.ViewGroup;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class TestModeResultsFragment extends Hilt_TestModeResultsFragment<androidx.viewbinding.a> {
    public final e j = new e(K.a(G.class), new b(this, 0), new b(this, 2), new b(this, 1));

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return "TestModeResultsFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 28);
    }
}
