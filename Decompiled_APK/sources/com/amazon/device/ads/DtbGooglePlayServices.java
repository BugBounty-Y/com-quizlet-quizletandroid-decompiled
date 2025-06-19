package com.amazon.device.ads;

import android.provider.Settings;

/* loaded from: classes.dex */
class DtbGooglePlayServices {
    private static final String LOG_TAG = "DtbGooglePlayServices";

    public static class AdvertisingInfo {
        private String advertisingIdentifier;
        private boolean gpsAvailable = true;
        private Boolean limitAdTrackingEnabled;

        public static AdvertisingInfo createNotAvailable() {
            return new AdvertisingInfo().setGooglePlayServicesAvailable(false);
        }

        private AdvertisingInfo setGooglePlayServicesAvailable(boolean z) {
            this.gpsAvailable = z;
            return this;
        }

        public String getAdvertisingIdentifier() {
            if (com.amazon.aps.ads.privacy.c.f.c()) {
                return this.advertisingIdentifier;
            }
            return null;
        }

        public boolean hasAdvertisingIdentifier() {
            return getAdvertisingIdentifier() != null;
        }

        public boolean isGooglePlayServicesAvailable() {
            return this.gpsAvailable;
        }

        public Boolean isLimitAdTrackingEnabled() {
            return this.limitAdTrackingEnabled;
        }

        public AdvertisingInfo setAdvertisingIdentifier(String str) {
            this.advertisingIdentifier = str;
            return this;
        }

        public AdvertisingInfo setLimitAdTrackingEnabled(Boolean bool) {
            this.limitAdTrackingEnabled = bool;
            return this;
        }
    }

    private boolean isAdvertisingClassAvailable() {
        return DtbCommonUtils.isClassAvailable("com.google.android.gms.ads.identifier.AdvertisingIdClient");
    }

    public AdvertisingInfo getAdvertisingIdentifierInfo() throws Settings.SettingNotFoundException {
        if (isAdvertisingClassAvailable()) {
            AdvertisingInfo advertisingIdentifierInfo = DtbGooglePlayServicesAdapter.newAdapter().getAdvertisingIdentifierInfo();
            if (advertisingIdentifierInfo.getAdvertisingIdentifier() != null && !advertisingIdentifierInfo.getAdvertisingIdentifier().isEmpty()) {
                return advertisingIdentifierInfo;
            }
        }
        AdvertisingInfo advertisingIdentifierInfo2 = DtbFireOSServiceAdapter.newAdapter().getAdvertisingIdentifierInfo();
        if (advertisingIdentifierInfo2.getAdvertisingIdentifier() != null && !advertisingIdentifierInfo2.getAdvertisingIdentifier().isEmpty()) {
            return advertisingIdentifierInfo2;
        }
        DtbLog.error(LOG_TAG, "The Google Play Services Advertising Identifier feature is not available. Please include the google dependency / check the proguard rule");
        com.amazon.aps.shared.a.e(1, 2, "The Google Play Services Advertising Identifier feature is not available", null);
        return AdvertisingInfo.createNotAvailable();
    }
}
