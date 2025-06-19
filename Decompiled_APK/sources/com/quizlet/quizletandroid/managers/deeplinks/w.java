package com.quizlet.quizletandroid.managers.deeplinks;

import android.app.TaskStackBuilder;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.quizlet.quizletandroid.ui.live.QuizletLiveDeepLinkInterstitialActivity;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class w implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String b;
    public static final List c;
    public static final List d;
    public final Uri a;

    static {
        String simpleName = w.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        b = simpleName;
        c = kotlin.collections.B.j("quizlet.live", "www.quizlet.live");
        d = kotlin.collections.B.j("live", "/live", "/live/");
    }

    public w(Uri uri) {
        Intrinsics.checkNotNullParameter(uri, "uri");
        this.a = uri;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        String str = QuizletLiveDeepLinkInterstitialActivity.s;
        Intrinsics.checkNotNullParameter(context, "context");
        Uri uri = this.a;
        Intrinsics.checkNotNullParameter(uri, "uri");
        Intent intent = new Intent(context, (Class<?>) QuizletLiveDeepLinkInterstitialActivity.class);
        intent.putExtra("live.uri", uri);
        Intent[] intents = TaskStackBuilder.create(context).addNextIntentWithParentStack(intent).getIntents();
        Intrinsics.checkNotNullExpressionValue(intents, "getIntents(...)");
        return intents;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final boolean b() {
        return true;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] c(Context context, h hVar) {
        return AbstractC3508o4.b(this, context, hVar);
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return b;
    }
}
