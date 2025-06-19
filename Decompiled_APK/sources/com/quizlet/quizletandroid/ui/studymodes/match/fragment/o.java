package com.quizlet.quizletandroid.ui.studymodes.match.fragment;

import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class o extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ MatchStartGameFragment b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ o(MatchStartGameFragment matchStartGameFragment, int i) {
        super(0);
        this.a = i;
        this.b = matchStartGameFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.requireActivity().getViewModelStore();
            case 1:
                return this.b.requireActivity().getDefaultViewModelCreationExtras();
            case 2:
                return this.b.requireActivity().getDefaultViewModelProviderFactory();
            default:
                return this.b;
        }
    }
}
