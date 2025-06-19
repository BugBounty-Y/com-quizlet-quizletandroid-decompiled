package com.quizlet.quizletandroid.ui.studymodes.assistant;

import android.widget.ProgressBar;
import androidx.compose.ui.platform.ComposeView;
import com.quizlet.quizletandroid.databinding.C4609m;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ LearningAssistantActivity b;

    public /* synthetic */ e(LearningAssistantActivity learningAssistantActivity, int i) {
        this.a = i;
        this.b = learningAssistantActivity;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        LearningAssistantActivity learningAssistantActivity = this.b;
        switch (this.a) {
            case 0:
                String str = LearningAssistantActivity.D;
                return ((C4609m) learningAssistantActivity.K()).c;
            case 1:
                String str2 = LearningAssistantActivity.D;
                ProgressBar loadingSpinner = ((C4609m) learningAssistantActivity.K()).f;
                Intrinsics.checkNotNullExpressionValue(loadingSpinner, "loadingSpinner");
                return loadingSpinner;
            case 2:
                String str3 = LearningAssistantActivity.D;
                ComposeView settingsView = ((C4609m) learningAssistantActivity.K()).h;
                Intrinsics.checkNotNullExpressionValue(settingsView, "settingsView");
                return settingsView;
            case 3:
                String str4 = LearningAssistantActivity.D;
                ComposeView onboardingView = ((C4609m) learningAssistantActivity.K()).g;
                Intrinsics.checkNotNullExpressionValue(onboardingView, "onboardingView");
                return onboardingView;
            case 4:
                com.onetrust.otpublishers.headless.UI.viewmodel.c cVar = learningAssistantActivity.u;
                if (cVar != null) {
                    return cVar;
                }
                Intrinsics.m("viewModelFactory");
                throw null;
            default:
                String str5 = LearningAssistantActivity.D;
                ((ComposeView) learningAssistantActivity.t.getValue()).setVisibility(8);
                return Unit.a;
        }
    }
}
