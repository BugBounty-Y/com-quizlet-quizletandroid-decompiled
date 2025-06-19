package com.quizlet.explanations.textbook.tableofcontents.ui;

import androidx.lifecycle.B0;
import androidx.lifecycle.viewmodel.c;
import androidx.lifecycle.y0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ TableOfContentsFragment b;

    public /* synthetic */ a(TableOfContentsFragment tableOfContentsFragment, int i) {
        this.a = i;
        this.b = tableOfContentsFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                B0 viewModelStore = this.b.requireParentFragment().getViewModelStore();
                Intrinsics.checkNotNullExpressionValue(viewModelStore, "<get-viewModelStore>(...)");
                return viewModelStore;
            case 1:
                c defaultViewModelCreationExtras = this.b.requireParentFragment().getDefaultViewModelCreationExtras();
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
                c defaultViewModelCreationExtras2 = this.b.requireParentFragment().getDefaultViewModelCreationExtras();
                Intrinsics.checkNotNullExpressionValue(defaultViewModelCreationExtras2, "<get-defaultViewModelCreationExtras>(...)");
                return defaultViewModelCreationExtras2;
            default:
                y0 defaultViewModelProviderFactory2 = this.b.requireParentFragment().getDefaultViewModelProviderFactory();
                Intrinsics.checkNotNullExpressionValue(defaultViewModelProviderFactory2, "<get-defaultViewModelProviderFactory>(...)");
                return defaultViewModelProviderFactory2;
        }
    }
}
