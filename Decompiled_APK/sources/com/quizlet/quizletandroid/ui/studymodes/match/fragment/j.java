package com.quizlet.quizletandroid.ui.studymodes.match.fragment;

import android.os.Bundle;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class j implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ MatchGameFragment b;

    public /* synthetic */ j(MatchGameFragment matchGameFragment, int i) {
        this.a = i;
        this.b = matchGameFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        MatchGameFragment matchGameFragment = this.b;
        switch (this.a) {
            case 0:
                String str = MatchGameFragment.m;
                return matchGameFragment.requireActivity().getDefaultViewModelCreationExtras();
            default:
                String str2 = MatchGameFragment.m;
                Bundle arguments = matchGameFragment.getArguments();
                return Boolean.valueOf(arguments != null ? arguments.getBoolean("ARG_PLAY_WITH_SELECTED", false) : false);
        }
    }
}
