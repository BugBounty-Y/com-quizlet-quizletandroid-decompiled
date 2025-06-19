package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.v, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3544v {
    public static final /* synthetic */ int a = 0;

    public static void a(Context context, Uri uri) {
        String strK;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(uri, "uri");
        if ("amzn".equals(uri.getScheme())) {
            com.amazon.aps.ads.c.a();
            strK = Intrinsics.k(uri.getQuery(), "https://www.amazon.com/gp/mas/dl/android?");
        } else {
            com.amazon.aps.ads.c.a();
            strK = "https://play.google.com/store/apps/" + ((Object) uri.getHost()) + '?' + ((Object) uri.getQuery());
        }
        Intent intent = new Intent("android.intent.action.VIEW");
        intent.setData(Uri.parse(strK));
        context.startActivity(intent);
    }
}
