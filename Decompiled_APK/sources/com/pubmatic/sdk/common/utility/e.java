package com.pubmatic.sdk.common.utility;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.webkit.URLUtil;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.pubmatic.sdk.common.log.POBLog;

/* loaded from: classes2.dex */
public class e {
    private static boolean a(Context context, Uri uri) {
        boolean z;
        if (triggerDeepLink(context, uri.toString(), false)) {
            POBLog.debug("PMDeepLinkUtil", "uri based deep link success!", android.support.v4.media.session.a.h(uri, "URL - "));
            return true;
        }
        String[] strArrSplit = uri.toString().split(";");
        int length = strArrSplit.length;
        int i = 0;
        while (true) {
            if (i >= length) {
                z = false;
                break;
            }
            String strA = a(strArrSplit[i]);
            if (strA != null && triggerDeepLink(context, strA, false)) {
                POBLog.debug("PMDeepLinkUtil", "fallback based deep link success!", "Fallback URL - ".concat(strA));
                z = true;
                break;
            }
            i++;
        }
        if (!z) {
            for (String str : strArrSplit) {
                String strB = b(str);
                if (strB != null && triggerDeepLink(context, strB, false)) {
                    POBLog.debug("PMDeepLinkUtil", "package based deep link success!", "Package URL - ".concat(strB));
                    return true;
                }
            }
        }
        return z;
    }

    private static String b(String str) {
        try {
            if (!str.contains("package")) {
                return null;
            }
            return "https://play.google.com/store/apps/details?id=" + Uri.decode(str).split(SimpleComparison.EQUAL_TO_OPERATION)[1];
        } catch (Exception e) {
            POBLog.error("PMDeepLinkUtil", e.getLocalizedMessage(), new Object[0]);
            return null;
        }
    }

    public static boolean triggerDeepLink(@NonNull Context context, @NonNull String str, boolean z) {
        try {
            Intent intent = new Intent("android.intent.action.VIEW");
            intent.addFlags(268435456);
            if (z) {
                intent.setPackage("com.android.vending");
            }
            intent.setData(Uri.parse(str));
            context.startActivity(intent);
            return true;
        } catch (ActivityNotFoundException unused) {
            POBLog.warn("PMDeepLinkUtil", AbstractC0147y.d("Activity not found for the uri: ", str), new Object[0]);
            return false;
        }
    }

    public static boolean validateAndRedirect(Context context, String str) {
        if (str == null || context == null) {
            return false;
        }
        if (o.isValidPlayStoreUrl(str) || !URLUtil.isValidUrl(str)) {
            return a(context, Uri.parse(str));
        }
        return false;
    }

    private static String a(String str) {
        String str2 = null;
        try {
            if (!str.contains("browser_fallback_url")) {
                return null;
            }
            str2 = Uri.decode(str).split(SimpleComparison.EQUAL_TO_OPERATION)[1];
            POBLog.debug("PMDeepLinkUtil", "Fall back url :" + str2, new Object[0]);
            return str2;
        } catch (Exception e) {
            POBLog.error("PMDeepLinkUtil", e.getLocalizedMessage(), new Object[0]);
            return str2;
        }
    }
}
