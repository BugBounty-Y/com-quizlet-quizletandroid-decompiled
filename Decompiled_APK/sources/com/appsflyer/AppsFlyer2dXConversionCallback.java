package com.appsflyer;

import androidx.annotation.NonNull;
import com.appsflyer.deeplink.DeepLinkListener;
import com.appsflyer.deeplink.DeepLinkResult;
import com.appsflyer.share.LinkGenerator;
import java.util.Map;
import org.json.JSONException;

/* loaded from: classes.dex */
public class AppsFlyer2dXConversionCallback implements AppsFlyerConversionListener, DeepLinkListener, LinkGenerator.ResponseListener {
    /* JADX WARN: Removed duplicated region for block: B:15:0x0039  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void AFAdRevenueData(java.lang.String r7, java.lang.String r8) throws org.json.JSONException {
        /*
            r6 = this;
            org.json.JSONObject r0 = new org.json.JSONObject     // Catch: org.json.JSONException -> L2b
            r0.<init>()     // Catch: org.json.JSONException -> L2b
            java.lang.String r1 = "status"
            java.lang.String r2 = "failure"
            r0.put(r1, r2)     // Catch: org.json.JSONException -> L2b
            java.lang.String r1 = "data"
            r0.put(r1, r8)     // Catch: org.json.JSONException -> L2b
            int r8 = r7.hashCode()     // Catch: org.json.JSONException -> L2b
            r1 = -1390007222(0xffffffffad262c4a, float:-9.445842E-12)
            r2 = 1
            if (r8 == r1) goto L2f
            r1 = 1050716216(0x3ea0a838, float:0.3137834)
            if (r8 == r1) goto L21
            goto L39
        L21:
            java.lang.String r8 = "onInstallConversionFailure"
            boolean r7 = r7.equals(r8)     // Catch: org.json.JSONException -> L2b
            if (r7 == 0) goto L39
            r7 = 0
            goto L3a
        L2b:
            r0 = move-exception
            r7 = r0
            r3 = r7
            goto L47
        L2f:
            java.lang.String r8 = "onAttributionFailure"
            boolean r7 = r7.equals(r8)     // Catch: org.json.JSONException -> L2b
            if (r7 == 0) goto L39
            r7 = r2
            goto L3a
        L39:
            r7 = -1
        L3a:
            if (r7 == 0) goto L43
            if (r7 == r2) goto L3f
            return
        L3f:
            r6.onAttributionFailureNative(r0)     // Catch: org.json.JSONException -> L2b
            return
        L43:
            r6.onInstallConversionFailureNative(r0)     // Catch: org.json.JSONException -> L2b
            return
        L47:
            com.appsflyer.AFLogger r0 = com.appsflyer.AFLogger.INSTANCE
            com.appsflyer.internal.AFg1cSDK r1 = com.appsflyer.internal.AFg1cSDK.OTHER
            r4 = 0
            r5 = 0
            java.lang.String r2 = "2dx error"
            r0.e(r1, r2, r3, r4, r5)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.AppsFlyer2dXConversionCallback.AFAdRevenueData(java.lang.String, java.lang.String):void");
    }

    @Override // com.appsflyer.AppsFlyerConversionListener
    public void onAppOpenAttribution(Map<String, String> map) {
        onAppOpenAttributionNative(map);
    }

    public native void onAppOpenAttributionNative(Object obj);

    @Override // com.appsflyer.AppsFlyerConversionListener
    public void onAttributionFailure(String str) throws JSONException {
        AFAdRevenueData("onInstallConversionFailure", str);
    }

    public native void onAttributionFailureNative(Object obj);

    @Override // com.appsflyer.AppsFlyerConversionListener
    public void onConversionDataFail(String str) throws JSONException {
        AFAdRevenueData("onAttributionFailure", str);
    }

    @Override // com.appsflyer.AppsFlyerConversionListener
    public void onConversionDataSuccess(Map<String, Object> map) {
        onInstallConversionDataLoadedNative(map);
    }

    @Override // com.appsflyer.deeplink.DeepLinkListener
    public void onDeepLinking(@NonNull DeepLinkResult deepLinkResult) {
        onDeepLinkingNative(deepLinkResult);
    }

    public native void onDeepLinkingNative(@NonNull DeepLinkResult deepLinkResult);

    public native void onInstallConversionDataLoadedNative(Object obj);

    public native void onInstallConversionFailureNative(Object obj);

    @Override // com.appsflyer.share.LinkGenerator.ResponseListener
    public void onResponse(String str) {
        onResponseNative(str);
    }

    @Override // com.appsflyer.share.LinkGenerator.ResponseListener
    public void onResponseError(String str) {
        onResponseErrorNative(str);
    }

    public native void onResponseErrorNative(String str);

    public native void onResponseNative(String str);
}
