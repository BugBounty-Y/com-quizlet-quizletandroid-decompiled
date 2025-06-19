package com.quizlet.quizletandroid.ui.learnpaywall;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class a extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ LearnPaywallFragment b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(LearnPaywallFragment learnPaywallFragment, int i) {
        super(0);
        this.a = i;
        this.b = learnPaywallFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.requireActivity().getViewModelStore();
            default:
                return this.b.requireActivity().getDefaultViewModelCreationExtras();
        }
    }
}
