package com.pubmatic.sdk.omsdk;

import android.content.Context;
import android.webkit.WebView;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import com.iab.omid.library.pubmatic.Omid;
import com.iab.omid.library.pubmatic.adsession.AdEvents;
import com.iab.omid.library.pubmatic.adsession.AdSession;
import com.iab.omid.library.pubmatic.adsession.AdSessionConfiguration;
import com.iab.omid.library.pubmatic.adsession.AdSessionContext;
import com.iab.omid.library.pubmatic.adsession.CreativeType;
import com.iab.omid.library.pubmatic.adsession.ImpressionType;
import com.iab.omid.library.pubmatic.adsession.Owner;
import com.iab.omid.library.pubmatic.adsession.Partner;
import com.pubmatic.sdk.common.log.POBLog;

@Keep
/* loaded from: classes2.dex */
public class POBHTMLMeasurement extends b implements com.pubmatic.sdk.common.viewability.b {
    @Override // com.pubmatic.sdk.common.viewability.b
    public void signalAdEvent(@NonNull com.pubmatic.sdk.common.viewability.a aVar) {
        if (this.adEvents == null) {
            POBLog.error(d.TAG, "Unable to signal event : %s", aVar.name());
            return;
        }
        try {
            POBLog.info(d.TAG, "Signaling event : %s", aVar.name());
            int i = a.a[aVar.ordinal()];
            if (i == 1) {
                this.adEvents.loaded();
            } else {
                if (i != 2) {
                    return;
                }
                this.adEvents.impressionOccurred();
            }
        } catch (Exception unused) {
            POBLog.error(d.TAG, "Unable to signal event : %s", aVar.name());
        }
    }

    @Override // com.pubmatic.sdk.common.viewability.b
    public void startAdSession(@NonNull WebView webView) {
        try {
            Context applicationContext = webView.getContext().getApplicationContext();
            if (!Omid.isActive()) {
                Omid.activate(applicationContext);
            }
            AdSession adSessionCreateAdSession = AdSession.createAdSession(AdSessionConfiguration.createAdSessionConfiguration(CreativeType.HTML_DISPLAY, ImpressionType.BEGIN_TO_RENDER, Owner.NATIVE, Owner.NONE, false), AdSessionContext.createHtmlAdSessionContext(Partner.createPartner("Pubmatic", "3.7.0"), webView, null, ""));
            this.adSession = adSessionCreateAdSession;
            adSessionCreateAdSession.registerAdView(webView);
            this.adEvents = AdEvents.createAdEvents(this.adSession);
            this.adSession.start();
            POBLog.debug(d.TAG, "Ad session started : %s", this.adSession.getAdSessionId());
        } catch (Exception e) {
            POBLog.error(d.TAG, "Unable to start session : %s", e.getMessage());
        }
    }
}
