package com.amazon.device.ads;

import android.provider.Settings;
import com.amazon.device.ads.DtbGooglePlayServices;

/* loaded from: classes.dex */
final class DtbAdvertisingInfo {
    private static final String LOG_TAG = "DtbAdvertisingInfo";

    public DtbAdvertisingInfo() throws Settings.SettingNotFoundException {
        if (AdRegistration.getContext() != null) {
            initializeAdvertisingInfo();
        } else {
            DtbLog.debugError("unable to initialize advertising info without setting app context");
            throw new IllegalArgumentException("unable to initialize advertising info without setting app context");
        }
    }

    private void initializeAdvertisingInfo() throws Settings.SettingNotFoundException {
        if (com.amazon.aps.ads.privacy.c.f.c()) {
            DtbLog.debug("Initializing advertising info using Google Play Service");
            DtbGooglePlayServices.AdvertisingInfo advertisingIdentifierInfo = new DtbGooglePlayServices().getAdvertisingIdentifierInfo();
            String advertisingIdentifier = advertisingIdentifierInfo.getAdvertisingIdentifier();
            String idfa = DtbSharedPreferences.getInstance().getIdfa();
            if (advertisingIdentifierInfo.hasAdvertisingIdentifier() && !DtbCommonUtils.isNullOrEmpty(advertisingIdentifier)) {
                if (DtbCommonUtils.isNullOrEmpty(idfa)) {
                    setIsAdvertisingIdentifierNew(true);
                    DtbLog.debug("Advertising identifier is new. Idfa=" + advertisingIdentifier);
                } else if (!DtbCommonUtils.isNullOrEmpty(idfa) && !idfa.equals(advertisingIdentifier)) {
                    setIsAdvertisingIdentifierChanged(true);
                    DtbLog.debug("Advertising identifier has changed. CurrentIdfa=" + advertisingIdentifier + " storedIdfa=" + idfa);
                }
            }
            if (!advertisingIdentifierInfo.hasAdvertisingIdentifier() && !DtbCommonUtils.isNullOrEmpty(idfa)) {
                setIsAdvertisingIdentifierNew(true);
            }
            if (!DtbCommonUtils.isNullOrEmpty(advertisingIdentifier)) {
                DtbSharedPreferences.getInstance().saveIdfa(advertisingIdentifier);
            }
            if (advertisingIdentifierInfo.isLimitAdTrackingEnabled() != null) {
                DtbSharedPreferences.getInstance().saveOptOut(advertisingIdentifierInfo.isLimitAdTrackingEnabled());
            }
            DtbLog.info(LOG_TAG, "Advertising identifier intialization process complete");
            DtbLog.debug("Google AdId intialized using Google Play Service. AdvertisingIdentifier=" + advertisingIdentifier + " isLimitAdTrackingEnabled=" + advertisingIdentifierInfo.isLimitAdTrackingEnabled());
        }
    }

    private void setIsAdvertisingIdentifierChanged(boolean z) {
        DtbSharedPreferences.getInstance().saveIsAdIdChanged(z);
    }

    private void setIsAdvertisingIdentifierNew(boolean z) {
        DtbSharedPreferences.getInstance().saveIsAdIdNew(z);
    }
}
