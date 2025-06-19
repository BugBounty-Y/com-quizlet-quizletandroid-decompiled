package com.amazon.device.ads;

/* loaded from: classes.dex */
class DtbGooglePlayServicesAdapter {
    public static DtbGooglePlayServicesAdapter newAdapter() {
        return new DtbGooglePlayServicesAdapter();
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0040  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x004b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.amazon.device.ads.DtbGooglePlayServices.AdvertisingInfo getAdvertisingIdentifierInfo() {
        /*
            r4 = this;
            r0 = 1
            android.content.Context r1 = com.amazon.device.ads.AdRegistration.getContext()     // Catch: java.lang.Exception -> La java.lang.IllegalArgumentException -> Lc com.google.android.gms.common.GooglePlayServicesRepairableException -> Le com.google.android.gms.common.GooglePlayServicesNotAvailableException -> L10 java.io.IOException -> L12 java.lang.IllegalStateException -> L14
            com.google.android.gms.ads.identifier.a r0 = com.google.android.gms.ads.identifier.b.a(r1)     // Catch: java.lang.Exception -> La java.lang.IllegalArgumentException -> Lc com.google.android.gms.common.GooglePlayServicesRepairableException -> Le com.google.android.gms.common.GooglePlayServicesNotAvailableException -> L10 java.io.IOException -> L12 java.lang.IllegalStateException -> L14
            goto L3e
        La:
            r1 = move-exception
            goto L16
        Lc:
            r1 = move-exception
            goto L1c
        Le:
            r1 = move-exception
            goto L22
        L10:
            r1 = move-exception
            goto L28
        L12:
            r1 = move-exception
            goto L32
        L14:
            r1 = move-exception
            goto L38
        L16:
            java.lang.String r2 = "Exception Occurred while retrieve Google Play Services Advertising Identifier"
            com.amazon.aps.shared.a.e(r0, r0, r2, r1)
            goto L3d
        L1c:
            java.lang.String r2 = "Illegal Argument passed to getAdvertisingIdInfo"
            com.amazon.aps.shared.a.e(r0, r0, r2, r1)
            goto L3d
        L22:
            java.lang.String r2 = "Retrieving the Google Play Services Advertising Identifier caused a GooglePlayServicesRepairableException."
            com.amazon.aps.shared.a.e(r0, r0, r2, r1)
            goto L3d
        L28:
            java.lang.String r2 = "Retrieving the Google Play Services Advertising Identifier caused a GooglePlayServicesNotAvailableException."
            com.amazon.aps.shared.a.e(r0, r0, r2, r1)
            com.amazon.device.ads.DtbGooglePlayServices$AdvertisingInfo r0 = com.amazon.device.ads.DtbGooglePlayServices.AdvertisingInfo.createNotAvailable()
            return r0
        L32:
            java.lang.String r2 = "Retrieving the Google Play Services Advertising Identifier caused an IOException."
            com.amazon.aps.shared.a.e(r0, r0, r2, r1)
            goto L3d
        L38:
            java.lang.String r2 = "Retrieving the Google Play Services  caused Illegal State Exception ( be sure the call was made from a non-background thread)."
            com.amazon.aps.shared.a.e(r0, r0, r2, r1)
        L3d:
            r0 = 0
        L3e:
            if (r0 != 0) goto L4b
            java.lang.String r0 = "The Google Play Services Advertising Identifier could not be retrieved."
            com.amazon.device.ads.DtbLog.debug(r0)
            com.amazon.device.ads.DtbGooglePlayServices$AdvertisingInfo r0 = new com.amazon.device.ads.DtbGooglePlayServices$AdvertisingInfo
            r0.<init>()
            return r0
        L4b:
            java.lang.String r1 = "The Google Play Services Advertising Identifier was successfully retrieved."
            com.amazon.device.ads.DtbLog.debug(r1)
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r2 = " Retrieved google ad id "
            r1.<init>(r2)
            java.lang.String r2 = r0.a
            r1.append(r2)
            java.lang.String r3 = " and tracking enabled : "
            r1.append(r3)
            boolean r0 = r0.b
            r1.append(r0)
            java.lang.String r1 = r1.toString()
            com.amazon.device.ads.DtbLog.debug(r1)
            com.amazon.device.ads.DtbGooglePlayServices$AdvertisingInfo r1 = new com.amazon.device.ads.DtbGooglePlayServices$AdvertisingInfo
            r1.<init>()
            com.amazon.device.ads.DtbGooglePlayServices$AdvertisingInfo r1 = r1.setAdvertisingIdentifier(r2)
            java.lang.Boolean r0 = java.lang.Boolean.valueOf(r0)
            com.amazon.device.ads.DtbGooglePlayServices$AdvertisingInfo r0 = r1.setLimitAdTrackingEnabled(r0)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.amazon.device.ads.DtbGooglePlayServicesAdapter.getAdvertisingIdentifierInfo():com.amazon.device.ads.DtbGooglePlayServices$AdvertisingInfo");
    }
}
