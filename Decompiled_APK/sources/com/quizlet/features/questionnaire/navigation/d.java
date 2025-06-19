package com.quizlet.features.questionnaire.navigation;

import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class d extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ QuestionnaireNavigationActivity b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(QuestionnaireNavigationActivity questionnaireNavigationActivity, int i) {
        super(0);
        this.a = i;
        this.b = questionnaireNavigationActivity;
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
