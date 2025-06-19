package com.quizlet.learn.ads;

import android.content.Context;
import com.quizlet.quizletandroid.t;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes3.dex */
public final class c {
    public final Context a;
    public final t b;
    public final u c;

    public c(Context context, t compositeDisposableProvider) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(compositeDisposableProvider, "compositeDisposableProvider");
        this.a = context;
        this.b = compositeDisposableProvider;
        this.c = l.b(new com.quizlet.featuregate.growthbook.a(this, 21));
    }
}
