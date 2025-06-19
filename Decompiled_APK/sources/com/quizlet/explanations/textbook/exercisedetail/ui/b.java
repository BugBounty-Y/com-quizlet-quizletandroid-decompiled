package com.quizlet.explanations.textbook.exercisedetail.ui;

import androidx.lifecycle.B0;
import androidx.lifecycle.y0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ExerciseDetailFragment b;

    public /* synthetic */ b(ExerciseDetailFragment exerciseDetailFragment, int i) {
        this.a = i;
        this.b = exerciseDetailFragment;
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
            case 2:
                y0 defaultViewModelProviderFactory = this.b.requireParentFragment().getDefaultViewModelProviderFactory();
                Intrinsics.checkNotNullExpressionValue(defaultViewModelProviderFactory, "<get-defaultViewModelProviderFactory>(...)");
                return defaultViewModelProviderFactory;
            case 3:
                B0 viewModelStore2 = this.b.requireParentFragment().getViewModelStore();
                Intrinsics.checkNotNullExpressionValue(viewModelStore2, "<get-viewModelStore>(...)");
                return viewModelStore2;
            case 4:
                androidx.lifecycle.viewmodel.c defaultViewModelCreationExtras2 = this.b.requireParentFragment().getDefaultViewModelCreationExtras();
                Intrinsics.checkNotNullExpressionValue(defaultViewModelCreationExtras2, "<get-defaultViewModelCreationExtras>(...)");
                return defaultViewModelCreationExtras2;
            default:
                y0 defaultViewModelProviderFactory2 = this.b.requireParentFragment().getDefaultViewModelProviderFactory();
                Intrinsics.checkNotNullExpressionValue(defaultViewModelProviderFactory2, "<get-defaultViewModelProviderFactory>(...)");
                return defaultViewModelProviderFactory2;
        }
    }
}
