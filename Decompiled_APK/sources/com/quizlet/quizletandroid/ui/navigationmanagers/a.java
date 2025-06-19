package com.quizlet.quizletandroid.ui.navigationmanagers;

import android.content.Context;
import com.quizlet.quizletandroid.t;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final Context a;
    public final t b;

    public a(Context context, t introIntentProvider) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(introIntentProvider, "introIntentProvider");
        this.a = context;
        this.b = introIntentProvider;
    }
}
