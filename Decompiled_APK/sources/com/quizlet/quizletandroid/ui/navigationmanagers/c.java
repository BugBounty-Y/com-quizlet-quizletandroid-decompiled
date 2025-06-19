package com.quizlet.quizletandroid.ui.navigationmanagers;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final Context a;

    public c(Context context) {
        com.quizlet.quizletandroid.ui.webpages.a webPageHelper = com.quizlet.quizletandroid.ui.webpages.a.a;
        Intrinsics.checkNotNullParameter(webPageHelper, "webPageHelper");
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }
}
