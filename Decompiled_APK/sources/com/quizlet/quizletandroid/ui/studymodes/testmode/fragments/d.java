package com.quizlet.quizletandroid.ui.studymodes.testmode.fragments;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class d extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ TestStudyModeResultsLoadingFragment b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(TestStudyModeResultsLoadingFragment testStudyModeResultsLoadingFragment, int i) {
        super(0);
        this.a = i;
        this.b = testStudyModeResultsLoadingFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.requireActivity().getViewModelStore();
            case 1:
                return this.b.requireActivity().getDefaultViewModelCreationExtras();
            default:
                return this.b.requireActivity().getDefaultViewModelProviderFactory();
        }
    }
}
