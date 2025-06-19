package com.pubmatic.sdk.openwrap.core;

import android.content.Context;
import android.view.View;
import androidx.annotation.NonNull;
import com.amazon.device.ads.DTBAdSize;
import com.pubmatic.sdk.video.c;
import com.pubmatic.sdk.video.player.n;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class u {

    public class a implements com.pubmatic.sdk.openwrap.core.banner.a {
        final /* synthetic */ Context a;
        final /* synthetic */ int b;

        public a(Context context, int i) {
            this.a = context;
            this.b = i;
        }

        @Override // com.pubmatic.sdk.openwrap.core.banner.a
        public com.pubmatic.sdk.common.ui.a build(@NonNull com.pubmatic.sdk.common.base.c cVar, int i) {
            if (cVar.isVideo()) {
                return u.videoRenderer(this.a, cVar, "inline", this.b, false);
            }
            return u.b(this.a, "inline", Math.max(cVar.getRefreshInterval(), 15), i);
        }
    }

    public class b implements com.pubmatic.sdk.openwrap.core.interstitial.a {
        final /* synthetic */ Context a;
        final /* synthetic */ int b;

        public b(Context context, int i) {
            this.a = context;
            this.b = i;
        }

        @Override // com.pubmatic.sdk.openwrap.core.interstitial.a
        public com.pubmatic.sdk.common.ui.a build(@NonNull com.pubmatic.sdk.common.base.c cVar, int i) {
            return cVar.isVideo() ? u.videoRenderer(this.a, cVar, DTBAdSize.AAX_INTERSTITIAL_AD_SIZE, this.b, false) : u.b(this.a, DTBAdSize.AAX_INTERSTITIAL_AD_SIZE, 15, i);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static com.pubmatic.sdk.common.ui.a b(@NonNull Context context, @NonNull String str, int i, int i2) {
        com.pubmatic.sdk.webrendering.mraid.e eVarCreateInstance = com.pubmatic.sdk.webrendering.mraid.e.createInstance(context.getApplicationContext(), str, i2);
        if (eVarCreateInstance != null) {
            eVarCreateInstance.setRenderingTimeout(i);
            eVarCreateInstance.setBaseURL(a());
            com.pubmatic.sdk.common.viewability.b bVar = (com.pubmatic.sdk.common.viewability.b) com.pubmatic.sdk.common.i.getSdkConfig().getMeasurementProvider("com.pubmatic.sdk.omsdk.POBHTMLMeasurement");
            if (bVar != null) {
                eVarCreateInstance.setHTMLMeasurementListener(bVar);
            }
        }
        return eVarCreateInstance;
    }

    @NonNull
    public static com.pubmatic.sdk.common.ui.a getBannerRenderer(@NonNull Context context, int i) {
        return new com.pubmatic.sdk.openwrap.core.banner.b(new a(context, i));
    }

    @NonNull
    public static com.pubmatic.sdk.common.ui.g getInterstitialRenderer(@NonNull Context context, int i) {
        return new com.pubmatic.sdk.openwrap.core.interstitial.b(context.getApplicationContext(), new b(context, i));
    }

    @NonNull
    public static com.pubmatic.sdk.video.renderer.c videoRenderer(@NonNull Context context, @NonNull com.pubmatic.sdk.common.base.c cVar, @NonNull String str, int i, boolean z) {
        com.pubmatic.sdk.webrendering.ui.q qVar;
        com.pubmatic.sdk.common.f fVar;
        boolean zEquals = DTBAdSize.AAX_INTERSTITIAL_AD_SIZE.equals(str);
        com.pubmatic.sdk.video.player.n nVarCreateInstance = com.pubmatic.sdk.video.player.n.createInstance(context, c.a.createVastConfig(cVar.getRawBid(), zEquals, z, !z, str));
        nVarCreateInstance.setPlacementType(str);
        nVarCreateInstance.setDeviceInfo(com.pubmatic.sdk.common.i.getDeviceInfo(context.getApplicationContext()));
        nVarCreateInstance.setMaxWrapperThreshold(3);
        nVarCreateInstance.setLinearity(n.a.LINEAR);
        nVarCreateInstance.setSkipabilityEnabled(zEquals);
        nVarCreateInstance.setShowEndCardOnSkip(!z && zEquals);
        boolean zA = a(cVar.getRawBid());
        nVarCreateInstance.setFSCEnabled(!zEquals || zA);
        nVarCreateInstance.setEnableLearnMoreButton((zEquals && zA) ? false : true);
        nVarCreateInstance.setBidBundleId(cVar.getBundle());
        if (zEquals) {
            qVar = new com.pubmatic.sdk.webrendering.ui.q(nVarCreateInstance);
        } else {
            qVar = new com.pubmatic.sdk.webrendering.ui.q((View) nVarCreateInstance, 50.0f);
            qVar.setAllowViewTreeObserverRegistration(true);
        }
        com.pubmatic.sdk.video.renderer.a aVar = new com.pubmatic.sdk.video.renderer.a(nVarCreateInstance, qVar, str);
        aVar.setMeasurementProvider((com.pubmatic.sdk.common.viewability.n) com.pubmatic.sdk.common.i.getSdkConfig().getMeasurementProvider("com.pubmatic.sdk.omsdk.POBVideoMeasurement"));
        if (zEquals) {
            fVar = com.pubmatic.sdk.common.utility.o.getInterstitialAdSize(context);
            aVar.setExpirationTimeout(i);
            aVar.disableIconClickCallbacks();
        } else {
            fVar = new com.pubmatic.sdk.common.f(cVar.getContentWidth(), cVar.getContentHeight());
        }
        nVarCreateInstance.setEndCardSize(fVar);
        return aVar;
    }

    @NonNull
    private static String a() {
        return com.pubmatic.sdk.common.i.getSdkConfig().isRequestSecureCreative() ? "https://ow.pubmatic.com/openrtb/2.5" : "http://ow.pubmatic.com/openrtb/2.5";
    }

    private static boolean a(JSONObject jSONObject) {
        JSONObject jSONObjectOptJSONObject;
        return (jSONObject == null || (jSONObjectOptJSONObject = jSONObject.optJSONObject("ext")) == null || jSONObjectOptJSONObject.optInt("fsc") != 1) ? false : true;
    }
}
