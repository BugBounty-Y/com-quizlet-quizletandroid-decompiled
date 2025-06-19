package com.pubmatic.sdk.omsdk;

import com.iab.omid.library.pubmatic.adsession.AdSession;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.omsdk.POBVideoMeasurement;

/* loaded from: classes2.dex */
public class g implements Runnable {
    final /* synthetic */ POBVideoMeasurement.a a;

    public g(POBVideoMeasurement.a aVar) {
        this.a = aVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        AdSession adSession = POBVideoMeasurement.this.adSession;
        if (adSession != null) {
            adSession.start();
            this.a.c.onOmidSessionInitialized();
            POBLog.debug(d.TAG, "Ad session started : %s", POBVideoMeasurement.this.adSession.getAdSessionId());
        }
    }
}
