package com.quizlet.features.blocks.ui;

import android.webkit.JavascriptInterface;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final Function0 a;
    public final Function0 b;

    public a(Function0 closeGame, Function0 redirectToLearn) {
        Intrinsics.checkNotNullParameter(closeGame, "closeGame");
        Intrinsics.checkNotNullParameter(redirectToLearn, "redirectToLearn");
        this.a = closeGame;
        this.b = redirectToLearn;
    }

    @JavascriptInterface
    public final void closeGame() {
        this.a.invoke();
    }

    @JavascriptInterface
    public final void redirectToLearn() {
        this.b.invoke();
    }
}
