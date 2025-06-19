package org.prebid.mobile.rendering.networking.tracking;

import android.os.AsyncTask;
import org.prebid.mobile.rendering.networking.BaseNetworkTask;
import org.prebid.mobile.rendering.utils.helpers.AppInfoManager;

/* loaded from: classes3.dex */
public abstract class ServerConnection {
    public static void a(String str) {
        BaseNetworkTask baseNetworkTask = new BaseNetworkTask(null);
        BaseNetworkTask.GetUrlParams getUrlParams = new BaseNetworkTask.GetUrlParams();
        getUrlParams.a = str;
        getUrlParams.e = "GET";
        getUrlParams.d = AppInfoManager.a;
        getUrlParams.c = "recordevents";
        baseNetworkTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, getUrlParams);
    }
}
