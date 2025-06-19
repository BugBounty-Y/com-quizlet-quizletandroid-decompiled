package org.prebid.mobile.rendering.sdk;

import android.os.Build;
import android.text.TextUtils;
import android.webkit.WebSettings;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.utils.helpers.AppInfoManager;

/* loaded from: classes3.dex */
public class UserAgentFetcherTask implements Runnable {
    @Override // java.lang.Runnable
    public final void run() {
        String strT;
        String strA;
        try {
            strT = WebSettings.getDefaultUserAgent(PrebidContextHolder.a());
        } catch (Exception unused) {
            LogUtil.b("UserAgentFetcherTask", "Failed to get user agent");
            strT = "";
        }
        if (TextUtils.isEmpty(strT) || strT.contains("UNAVAILABLE")) {
            StringBuilder sb = new StringBuilder("Mozilla/5.0 (Linux; U; Android ");
            sb.append(Build.VERSION.RELEASE);
            sb.append("; ");
            String str = Build.MANUFACTURER;
            String str2 = Build.MODEL;
            if (str2.startsWith(str)) {
                strA = AppInfoManager.a(str2);
            } else {
                strA = AppInfoManager.a(str) + " " + str2;
            }
            strT = android.support.v4.media.session.a.t(sb, strA, ")");
        }
        AppInfoManager.a = strT;
    }
}
