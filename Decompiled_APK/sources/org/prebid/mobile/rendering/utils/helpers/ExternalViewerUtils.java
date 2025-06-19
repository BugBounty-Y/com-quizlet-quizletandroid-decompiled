package org.prebid.mobile.rendering.utils.helpers;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.support.v4.media.session.a;
import android.util.Log;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.utils.url.ActionNotResolvedException;

/* loaded from: classes3.dex */
public abstract class ExternalViewerUtils {
    public static boolean a(Context context, Intent intent) {
        if (context != null) {
            return context.getPackageManager().queryIntentActivities(intent, 65536).size() > 0;
        }
        LogUtil.e(3, "ExternalViewerUtils", "isActivityCallable(): returning false. Intent or context is null");
        return false;
    }

    public static void b(Context context, Uri uri) throws ActionNotResolvedException {
        Intent intent = new Intent("android.intent.action.VIEW", uri);
        if (!a(context, intent)) {
            throw new ActionNotResolvedException(a.h(uri, "launchApplicationUrl: Failure. No activity was found to handle action for "));
        }
        if (!(context instanceof Activity)) {
            intent.addFlags(268435456);
        }
        try {
            c(context, intent);
        } catch (ActivityNotFoundException e) {
            throw new ActionNotResolvedException(e);
        }
    }

    public static void c(Context context, Intent intent) {
        if (context == null) {
            Log.e("ExternalViewerUtils", "Can't start activity!");
            return;
        }
        if (!(context instanceof Activity)) {
            intent.addFlags(268435456);
        }
        context.startActivity(intent);
    }
}
