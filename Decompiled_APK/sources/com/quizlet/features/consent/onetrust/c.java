package com.quizlet.features.consent.onetrust;

import com.onetrust.otpublishers.headless.Public.OTEventListener;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReason;
import com.quizlet.learn.ads.g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends OTEventListener {
    public final g a;

    public c(g onDismiss) {
        Intrinsics.checkNotNullParameter(onDismiss, "onDismiss");
        this.a = onDismiss;
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void allSDKViewsDismissed(String str) {
        this.a.invoke();
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onBannerClickedAcceptAll() {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onBannerClickedRejectAll() {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onHideBanner() {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onHidePreferenceCenter() {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onHideVendorList() {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onPreferenceCenterAcceptAll() {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onPreferenceCenterConfirmChoices() {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onPreferenceCenterPurposeConsentChanged(String str, int i) {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onPreferenceCenterPurposeLegitimateInterestChanged(String str, int i) {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onPreferenceCenterRejectAll() {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onShowBanner(OTUIDisplayReason oTUIDisplayReason) {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onShowPreferenceCenter(OTUIDisplayReason oTUIDisplayReason) {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onShowVendorList() {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onVendorConfirmChoices() {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onVendorListVendorConsentChanged(String str, int i) {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTEventListener
    public final void onVendorListVendorLegitimateInterestChanged(String str, int i) {
    }
}
