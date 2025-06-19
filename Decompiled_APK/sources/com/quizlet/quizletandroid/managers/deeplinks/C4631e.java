package com.quizlet.quizletandroid.managers.deeplinks;

import android.app.TaskStackBuilder;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.quizlet.quizletandroid.ui.group.GroupActivity;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.managers.deeplinks.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4631e implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String d;
    public final Uri a;
    public final Long b;
    public final String c;

    static {
        String simpleName = C4631e.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        d = simpleName;
    }

    public C4631e(Uri uri, Long l, String str) {
        Intrinsics.checkNotNullParameter(uri, "uri");
        this.a = uri;
        this.b = l;
        this.c = str;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Long l = this.b;
        String str = this.c;
        boolean z = (str == null || l == null) ? false : true;
        String str2 = GroupActivity.u;
        Intent[] intents = TaskStackBuilder.create(context).addNextIntentWithParentStack(com.quizlet.quizletandroid.ui.group.f.a(context, l, this.a, z, str)).getIntents();
        Intrinsics.checkNotNullExpressionValue(intents, "getIntents(...)");
        return intents;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final boolean b() {
        return false;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] c(Context context, h hVar) {
        return AbstractC3508o4.b(this, context, hVar);
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return d;
    }
}
