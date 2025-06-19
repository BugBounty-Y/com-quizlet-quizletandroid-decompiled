package com.quizlet.features.onboarding.ell;

import androidx.fragment.app.AbstractC1136h0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o implements com.quizlet.features.infra.navigation.o {
    @Override // com.quizlet.features.infra.navigation.o
    public final void a(AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        if (fragmentManager.R()) {
            return;
        }
        String str = OnboardingELLBottomSheetFragment.w;
        if (fragmentManager.E(str) != null) {
            return;
        }
        new OnboardingELLBottomSheetFragment().O(fragmentManager, str);
    }
}
