package com.quizlet.quizletandroid.ui.navigationmanagers;

import android.content.Context;
import com.quizlet.quizletandroid.t;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h {
    public final Context a;
    public final t b;
    public final com.quizlet.features.consent.onetrust.d c;

    public h(Context context, t introIntentProvider, com.quizlet.features.consent.onetrust.d oneTrustConsentManager) {
        com.quizlet.quizletandroid.ui.webpages.a webPageHelper = com.quizlet.quizletandroid.ui.webpages.a.a;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(webPageHelper, "webPageHelper");
        Intrinsics.checkNotNullParameter(introIntentProvider, "introIntentProvider");
        Intrinsics.checkNotNullParameter(oneTrustConsentManager, "oneTrustConsentManager");
        this.a = context;
        this.b = introIntentProvider;
        this.c = oneTrustConsentManager;
    }
}
