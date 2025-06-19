package com.quizlet.features.onboarding.ell;

import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class d extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ OnboardingELLBottomSheetFragment b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(OnboardingELLBottomSheetFragment onboardingELLBottomSheetFragment, int i) {
        super(0);
        this.a = i;
        this.b = onboardingELLBottomSheetFragment;
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
