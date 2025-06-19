package com.quizlet.facebook;

import android.content.Context;
import com.facebook.internal.AbstractC1554i;
import com.facebook.o;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class b {
    public final Context a;

    public b(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    public final void a(Function0 onInitialized) {
        Intrinsics.checkNotNullParameter(onInitialized, "onInitialized");
        if (o.o.get()) {
            onInitialized.invoke();
            return;
        }
        String applicationId = this.a.getApplicationContext().getString(R.string.facebook_app_id);
        Intrinsics.checkNotNullExpressionValue(applicationId, "getString(...)");
        Intrinsics.checkNotNullParameter(applicationId, "applicationId");
        AbstractC1554i.h(applicationId, "applicationId");
        o.d = applicationId;
        o.f = this.a.getApplicationContext().getString(R.string.facebook_client_token);
        o.k(this.a, new com.google.android.material.search.a(onInitialized, 18));
    }
}
