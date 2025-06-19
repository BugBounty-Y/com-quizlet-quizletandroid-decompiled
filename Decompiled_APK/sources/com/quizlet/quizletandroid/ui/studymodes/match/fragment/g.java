package com.quizlet.quizletandroid.ui.studymodes.match.fragment;

import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class g implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ MatchEndGameFragment b;

    public /* synthetic */ g(MatchEndGameFragment matchEndGameFragment, int i) {
        this.a = i;
        this.b = matchEndGameFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        MatchEndGameFragment matchEndGameFragment = this.b;
        switch (this.a) {
            case 0:
                String str = MatchEndGameFragment.p;
                return matchEndGameFragment.requireActivity().getDefaultViewModelCreationExtras();
            case 1:
                String str2 = MatchEndGameFragment.p;
                return Long.valueOf(matchEndGameFragment.requireArguments().getLong("ARG_END_TIME"));
            case 2:
                String str3 = MatchEndGameFragment.p;
                return Long.valueOf(matchEndGameFragment.requireArguments().getLong("ARG_FINAL_PENALTY"));
            default:
                String str4 = MatchEndGameFragment.p;
                return Long.valueOf(matchEndGameFragment.requireArguments().getLong("ARG_ELAPSED_TIME"));
        }
    }
}
