package com.pubmatic.sdk.omsdk;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
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
import com.iab.omid.library.pubmatic.adsession.VerificationScriptResource;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.viewability.j;
import java.util.List;

@Keep
/* loaded from: classes2.dex */
public class POBNativeMeasurement extends b implements com.pubmatic.sdk.common.viewability.g {

    @NonNull
    private final Handler handler = new Handler(Looper.getMainLooper());

    public class a implements com.pubmatic.sdk.common.viewability.c {
        final /* synthetic */ List a;
        final /* synthetic */ View b;
        final /* synthetic */ com.pubmatic.sdk.common.viewability.f c;

        public a(List list, View view, com.pubmatic.sdk.common.viewability.f fVar) {
            this.a = list;
            this.b = view;
        }

        @Override // com.pubmatic.sdk.common.viewability.c
        public void onMeasurementScriptReceived(@NonNull String str) {
            AdSessionContext adSessionContextCreateNativeAdSessionContext = AdSessionContext.createNativeAdSessionContext(Partner.createPartner("Pubmatic", "3.7.0"), str, this.a, null, "");
            AdSessionConfiguration adSessionConfigurationCreateAdSessionConfiguration = AdSessionConfiguration.createAdSessionConfiguration(CreativeType.NATIVE_DISPLAY, ImpressionType.BEGIN_TO_RENDER, Owner.NATIVE, Owner.NONE, false);
            POBNativeMeasurement.this.adSession = AdSession.createAdSession(adSessionConfigurationCreateAdSessionConfiguration, adSessionContextCreateNativeAdSessionContext);
            POBNativeMeasurement.this.adSession.registerAdView(this.b);
            POBNativeMeasurement pOBNativeMeasurement = POBNativeMeasurement.this;
            pOBNativeMeasurement.adEvents = AdEvents.createAdEvents(pOBNativeMeasurement.adSession);
            POBNativeMeasurement.this.handler.post(new f(this));
        }
    }

    @Override // com.pubmatic.sdk.common.viewability.g
    public void signalAdEvent(@NonNull com.pubmatic.sdk.common.viewability.e eVar) {
        if (this.adEvents == null) {
            POBLog.error(d.TAG, "Unable to signal event : %s", eVar.name());
            return;
        }
        try {
            POBLog.info(d.TAG, "Signaling event : %s", eVar.name());
            int i = c.a[eVar.ordinal()];
            if (i == 1) {
                this.adEvents.loaded();
            } else if (i != 2) {
                POBLog.warn(d.TAG, "Unable to signal event : %s", eVar.name());
            } else {
                this.adEvents.impressionOccurred();
            }
        } catch (Exception unused) {
            POBLog.error(d.TAG, "Unable to signal event : %s", eVar.name());
        }
    }

    @Override // com.pubmatic.sdk.common.viewability.g
    public void startAdSession(@NonNull View view, List<? extends j> list, @NonNull com.pubmatic.sdk.common.viewability.f fVar) {
        try {
            List<VerificationScriptResource> verificationScriptResourceList = d.getVerificationScriptResourceList(list);
            if (verificationScriptResourceList.isEmpty()) {
                POBLog.error(d.TAG, "Unable to start session : %s", "Verification list is empty");
                fVar.a();
            } else {
                Context applicationContext = view.getContext().getApplicationContext();
                if (!Omid.isActive()) {
                    Omid.activate(applicationContext);
                }
                omidJsServiceScript(applicationContext, new a(verificationScriptResourceList, view, fVar));
            }
        } catch (Exception e) {
            POBLog.error(d.TAG, "Unable to start session : %s", e.getMessage());
        }
    }
}
