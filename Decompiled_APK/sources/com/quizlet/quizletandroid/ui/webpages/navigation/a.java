package com.quizlet.quizletandroid.ui.webpages.navigation;

import android.content.Context;
import android.net.Uri;
import com.quizlet.features.infra.navigation.D;
import com.quizlet.ui.models.webpage.i;
import com.quizlet.ui.models.webpage.m;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements D {
    public final Context a;

    public a(Context context) {
        com.quizlet.quizletandroid.ui.webpages.a webPageHelper = com.quizlet.quizletandroid.ui.webpages.a.a;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(webPageHelper, "webPageHelper");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.D
    public final void D(m webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        com.quizlet.quizletandroid.ui.webpages.a.a.c(this.a, webPage);
    }

    @Override // com.quizlet.features.infra.navigation.D
    public final void H() {
        D(i.c);
    }

    @Override // com.quizlet.features.infra.navigation.D
    public final void p(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        com.quizlet.quizletandroid.ui.webpages.a.a.a(this.a, Uri.parse(url));
    }
}
