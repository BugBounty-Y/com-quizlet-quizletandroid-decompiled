package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class q extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ LearnRoundSummaryFragment b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ q(LearnRoundSummaryFragment learnRoundSummaryFragment, int i) {
        super(0);
        this.a = i;
        this.b = learnRoundSummaryFragment;
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
