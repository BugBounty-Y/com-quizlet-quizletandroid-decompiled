package com.quizlet.explanations.solution.fragments;

import androidx.lifecycle.B0;
import androidx.lifecycle.y0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ExplanationsSolutionFragment b;

    public /* synthetic */ c(ExplanationsSolutionFragment explanationsSolutionFragment, int i) {
        this.a = i;
        this.b = explanationsSolutionFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                B0 viewModelStore = this.b.requireParentFragment().getViewModelStore();
                Intrinsics.checkNotNullExpressionValue(viewModelStore, "<get-viewModelStore>(...)");
                return viewModelStore;
            case 1:
                androidx.lifecycle.viewmodel.c defaultViewModelCreationExtras = this.b.requireParentFragment().getDefaultViewModelCreationExtras();
                Intrinsics.checkNotNullExpressionValue(defaultViewModelCreationExtras, "<get-defaultViewModelCreationExtras>(...)");
                return defaultViewModelCreationExtras;
            default:
                y0 defaultViewModelProviderFactory = this.b.requireParentFragment().getDefaultViewModelProviderFactory();
                Intrinsics.checkNotNullExpressionValue(defaultViewModelProviderFactory, "<get-defaultViewModelProviderFactory>(...)");
                return defaultViewModelProviderFactory;
        }
    }
}
