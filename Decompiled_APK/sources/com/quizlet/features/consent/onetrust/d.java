package com.quizlet.features.consent.onetrust;

import android.webkit.WebView;
import androidx.fragment.app.I;
import com.onetrust.otpublishers.headless.Public.DataModel.OTSdkParams;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;
import com.quizlet.learn.ads.g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d {
    public final OTSdkParams a;
    public final dagger.internal.a b;

    public d(OTSdkParams oTSdkParams, dagger.internal.a oTPublishersHeadlessSDK) {
        com.quizlet.qutils.i18n.a localeUtil = com.quizlet.qutils.i18n.a.a;
        a domainIdForOneTrust = a.a;
        Intrinsics.checkNotNullParameter(oTSdkParams, "oTSdkParams");
        Intrinsics.checkNotNullParameter(oTPublishersHeadlessSDK, "oTPublishersHeadlessSDK");
        Intrinsics.checkNotNullParameter(localeUtil, "localeUtil");
        Intrinsics.checkNotNullParameter(domainIdForOneTrust, "domainIdForOneTrust");
        this.a = oTSdkParams;
        this.b = oTPublishersHeadlessSDK;
    }

    public static final void a(d dVar, OTResponse oTResponse, String str) {
        dVar.getClass();
        timber.log.c.a.g(android.support.v4.media.session.a.B("ASC-OTSDK ", str, " responseCode: %d, responseMessage: %s"), Integer.valueOf(oTResponse.getResponseCode()), oTResponse.getResponseMessage());
    }

    public final boolean b(I activity, g gVar) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        if (a.b) {
            return false;
        }
        dagger.internal.a aVar = this.b;
        if (!((OTPublishersHeadlessSDK) aVar.get()).shouldShowBanner()) {
            return false;
        }
        if (gVar != null) {
            ((OTPublishersHeadlessSDK) aVar.get()).addEventListener(new c(gVar));
        }
        ((OTPublishersHeadlessSDK) aVar.get()).showBannerUI(activity);
        a.b = true;
        return true;
    }

    public final void c(WebView webView) {
        Intrinsics.checkNotNullParameter(webView, "webView");
        webView.evaluateJavascript("javascript:" + ((OTPublishersHeadlessSDK) this.b.get()).getOTConsentJSForWebView(), null);
    }
}
