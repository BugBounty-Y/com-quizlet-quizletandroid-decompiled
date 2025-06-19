package com.pubmatic.sdk.omsdk;

import com.iab.omid.library.pubmatic.adsession.AdSession;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.omsdk.POBNativeMeasurement;

/* loaded from: classes2.dex */
public class f implements Runnable {
    final /* synthetic */ POBNativeMeasurement.a a;

    public f(POBNativeMeasurement.a aVar) {
        this.a = aVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        AdSession adSession = POBNativeMeasurement.this.adSession;
        if (adSession == null) {
            return;
        }
        adSession.start();
        POBLog.debug(d.TAG, "Ad session started : %s", POBNativeMeasurement.this.adSession.getAdSessionId());
        this.a.getClass();
        throw null;
    }
}
