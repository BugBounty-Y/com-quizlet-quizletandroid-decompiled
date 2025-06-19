package com.quizlet.security.challenge.viewmodel;

import android.webkit.JavascriptInterface;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final com.quizlet.security.challenge.ui.b a;

    public a(com.quizlet.security.challenge.ui.b onChallengeSolved) {
        Intrinsics.checkNotNullParameter(onChallengeSolved, "onChallengeSolved");
        this.a = onChallengeSolved;
    }

    @JavascriptInterface
    public final void onChallengeSolved() {
        this.a.invoke();
    }
}
