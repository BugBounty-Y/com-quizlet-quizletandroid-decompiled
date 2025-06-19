package org.prebid.mobile.rendering.networking.modelcontrollers;

import org.prebid.mobile.LogUtil;
import org.prebid.mobile.api.exceptions.AdException;
import org.prebid.mobile.configuration.AdUnitConfiguration;
import org.prebid.mobile.rendering.networking.ResponseHandler;
import org.prebid.mobile.rendering.networking.urlBuilder.URLBuilder;

/* loaded from: classes3.dex */
public abstract class Requester {
    public String a;
    public AdUnitConfiguration b;
    public URLBuilder c;
    public ResponseHandler d;

    public final void a(String str, String str2) {
        LogUtil.e(5, "Requester", str);
        AdException adException = new AdException("Initialization failed", str2);
        ResponseHandler responseHandler = this.d;
        if (responseHandler != null) {
            responseHandler.a(adException);
        }
    }
}
