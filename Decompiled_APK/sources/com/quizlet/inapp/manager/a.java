package com.quizlet.inapp.manager;

import android.content.Context;
import com.google.android.play.core.review.b;
import com.google.android.play.core.review.d;
import com.quizlet.data.repository.searchexplanations.c;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final c a;
    public final b b;

    public a(Context context, c appReviewSharedPrefs) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(appReviewSharedPrefs, "appReviewSharedPrefs");
        this.a = appReviewSharedPrefs;
        Context applicationContext = context.getApplicationContext();
        b bVar = new b(new d(applicationContext != null ? applicationContext : context));
        Intrinsics.checkNotNullExpressionValue(bVar, "create(...)");
        this.b = bVar;
    }
}
