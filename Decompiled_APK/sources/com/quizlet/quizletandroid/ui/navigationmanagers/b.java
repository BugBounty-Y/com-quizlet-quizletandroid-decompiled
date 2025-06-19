package com.quizlet.quizletandroid.ui.navigationmanagers;

import android.content.Context;
import android.content.Intent;
import androidx.core.app.W;
import com.google.android.gms.internal.mlkit_vision_document_scanner.B;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import com.quizlet.explanations.textbook.ui.TextbookActivity;
import com.quizlet.login.LoginNavActivity;
import com.quizlet.quizletandroid.t;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.internal.platform.m;

/* loaded from: classes3.dex */
public final class b implements com.quizlet.explanations.navigation.b {
    public final Context a;
    public final t b;

    public b(Context context, t loginIntentProvider) {
        com.quizlet.quizletandroid.ui.webpages.a webPageHelper = com.quizlet.quizletandroid.ui.webpages.a.a;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(webPageHelper, "webPageHelper");
        Intrinsics.checkNotNullParameter(loginIntentProvider, "loginIntentProvider");
        this.a = context;
        this.b = loginIntentProvider;
    }

    public final void a(Context context, Intent redirectIntent) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(redirectIntent, "redirectIntent");
        Intent intent = (Intent) this.b.get();
        W w = new W(context);
        w.a(redirectIntent);
        w.a.add(intent);
        w.e();
    }

    public final void b(Context context, Intent redirectIntent) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(redirectIntent, "redirectIntent");
        String str = LoginNavActivity.i;
        Intent intentC = B.c(context, false);
        W w = new W(context);
        w.a(redirectIntent);
        w.a.add(intentC);
        w.e();
    }

    public final void c(Context context, TextbookSetUpState setUpState) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(setUpState, "setUpState");
        String str = TextbookActivity.r;
        context.startActivity(m.c(context, setUpState));
    }
}
