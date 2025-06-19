package org.prebid.mobile.rendering.networking;

import org.prebid.mobile.rendering.networking.BaseNetworkTask;

/* loaded from: classes3.dex */
public interface ResponseHandler extends BaseResponseHandler {
    void a(Exception exc);

    void b(BaseNetworkTask.GetUrlResult getUrlResult);

    void c(String str);
}
