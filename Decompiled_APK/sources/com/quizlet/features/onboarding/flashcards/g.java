package com.quizlet.features.onboarding.flashcards;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class g extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ OnboardingFlashcardsActivity b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(OnboardingFlashcardsActivity onboardingFlashcardsActivity, int i) {
        super(0);
        this.a = i;
        this.b = onboardingFlashcardsActivity;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.getDefaultViewModelProviderFactory();
            case 1:
                return this.b.getViewModelStore();
            default:
                return this.b.getDefaultViewModelCreationExtras();
        }
    }
}
