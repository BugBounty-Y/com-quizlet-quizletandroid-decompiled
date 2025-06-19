package com.quizlet.quizletandroid.ui.navigationmanagers;

import com.quizlet.search.navigation.m;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements m {
    public final com.quizlet.data.interactor.school.b a;

    public g(com.quizlet.data.interactor.school.b quizletLiveNavigationManager) {
        com.quizlet.quizletandroid.ui.webpages.a webPageHelper = com.quizlet.quizletandroid.ui.webpages.a.a;
        Intrinsics.checkNotNullParameter(quizletLiveNavigationManager, "quizletLiveNavigationManager");
        Intrinsics.checkNotNullParameter(webPageHelper, "webPageHelper");
        this.a = quizletLiveNavigationManager;
    }
}
