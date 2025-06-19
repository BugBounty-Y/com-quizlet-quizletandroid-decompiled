package org.prebid.mobile.rendering.sdk;

import android.os.AsyncTask;
import android.util.Log;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.PrebidMobile;
import org.prebid.mobile.rendering.networking.BaseNetworkTask;
import org.prebid.mobile.rendering.networking.ResponseHandler;
import org.prebid.mobile.rendering.utils.helpers.AppInfoManager;

/* loaded from: classes3.dex */
public class StatusRequester implements Callable<String> {

    public static class ResultHolder {
        public String a;
        public final AtomicBoolean b = new AtomicBoolean(false);
    }

    @Override // java.util.concurrent.Callable
    public final String call() throws InterruptedException {
        String str = PrebidMobile.c.a;
        if (!str.contains("/openrtb2/auction")) {
            LogUtil.e(4, "PrebidMobile", "Prebid SDK can't build the /status endpoint. Please, provide the custom /status endpoint using PrebidMobile.setCustomStatusEndpoint().");
            return null;
        }
        String strReplace = str.replace("/openrtb2/auction", "/status");
        final ResultHolder resultHolder = new ResultHolder();
        try {
            BaseNetworkTask baseNetworkTask = new BaseNetworkTask(new ResponseHandler() { // from class: org.prebid.mobile.rendering.sdk.StatusRequester.1
                @Override // org.prebid.mobile.rendering.networking.ResponseHandler
                public final void a(Exception exc) {
                    String str2 = "Prebid Server is not responding: " + exc.getMessage();
                    ResultHolder resultHolder2 = resultHolder;
                    resultHolder2.b.set(true);
                    resultHolder2.a = str2;
                }

                @Override // org.prebid.mobile.rendering.networking.ResponseHandler
                public final void b(BaseNetworkTask.GetUrlResult getUrlResult) {
                    int i = getUrlResult.c;
                    ResultHolder resultHolder2 = resultHolder;
                    AtomicBoolean atomicBoolean = resultHolder2.b;
                    if (i < 200 || i >= 300) {
                        atomicBoolean.set(true);
                        resultHolder2.a = "Server status is not ok!";
                    } else {
                        atomicBoolean.set(true);
                        resultHolder2.a = null;
                    }
                }

                @Override // org.prebid.mobile.rendering.networking.ResponseHandler
                public final void c(String str2) {
                    String strConcat = "Prebid Server is not responding: ".concat(str2);
                    ResultHolder resultHolder2 = resultHolder;
                    resultHolder2.b.set(true);
                    resultHolder2.a = strConcat;
                }
            });
            BaseNetworkTask.GetUrlParams getUrlParams = new BaseNetworkTask.GetUrlParams();
            getUrlParams.a = strReplace;
            getUrlParams.e = "GET";
            getUrlParams.d = AppInfoManager.a;
            getUrlParams.c = "StatusTask";
            baseNetworkTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, getUrlParams);
            while (!resultHolder.b.get()) {
                Thread.sleep(25L);
            }
        } catch (InterruptedException e) {
            LogUtil.e(3, "StatusRequester", "InterruptedException: " + Log.getStackTraceString(e));
        }
        return resultHolder.a;
    }
}
