package org.prebid.mobile.rendering.networking.parameters;

import android.content.Context;
import android.text.TextUtils;
import java.util.HashMap;
import org.json.JSONException;
import org.json.JSONObject;
import org.prebid.mobile.PrebidMobile;
import org.prebid.mobile.TargetingParams;
import org.prebid.mobile.rendering.models.openrtb.BidRequest;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.App;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.Ext;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.apps.Publisher;
import org.prebid.mobile.rendering.sdk.PrebidContextHolder;
import org.prebid.mobile.rendering.utils.helpers.AppInfoManager;
import org.prebid.mobile.rendering.utils.helpers.Utils;

/* loaded from: classes3.dex */
public class AppInfoParameterBuilder extends ParameterBuilder {
    @Override // org.prebid.mobile.rendering.networking.parameters.ParameterBuilder
    public final void a(AdRequestInput adRequestInput) throws JSONException {
        String packageName;
        Context contextA;
        BidRequest bidRequest = adRequestInput.a;
        if (bidRequest.b == null) {
            bidRequest.b = new App();
        }
        App app2 = bidRequest.b;
        if (app2.f == null) {
            app2.f = new Publisher();
        }
        app2.f.a = PrebidMobile.b;
        String str = AppInfoManager.c;
        if (Utils.c(str)) {
            app2.a = str;
        }
        String str2 = AppInfoManager.d;
        if (Utils.c(str2)) {
            app2.e = str2;
        }
        HashMap map = TargetingParams.a;
        synchronized (TargetingParams.class) {
            packageName = (!TextUtils.isEmpty(null) || (contextA = PrebidContextHolder.a()) == null) ? null : contextA.getPackageName();
        }
        if (Utils.c(packageName)) {
            app2.b = packageName;
        } else if (Utils.c(AppInfoManager.b)) {
            app2.b = AppInfoManager.b;
        }
        synchronized (TargetingParams.class) {
        }
        if (Utils.c("")) {
            app2.d = "";
        }
        if (Utils.c(null)) {
            if (app2.f == null) {
                app2.f = new Publisher();
            }
            app2.f.getClass();
        }
        synchronized (TargetingParams.class) {
        }
        if (Utils.c("")) {
            app2.c = "";
        }
        if (app2.g == null) {
            app2.g = new Ext();
        }
        Ext ext = app2.g;
        JSONObject jSONObject = new JSONObject();
        Utils.a(jSONObject, "source", "prebid-mobile");
        Utils.a(jSONObject, "version", "3.0.0");
        ext.a.put("prebid", jSONObject);
        HashMap map2 = TargetingParams.d;
        if (map2.isEmpty()) {
            return;
        }
        if (app2.g == null) {
            app2.g = new Ext();
        }
        app2.g.a.put("data", Utils.d(map2));
    }
}
