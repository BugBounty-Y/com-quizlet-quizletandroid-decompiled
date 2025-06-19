package org.prebid.mobile.rendering.sdk.deviceData.managers;

import android.content.Context;
import android.location.Location;
import android.location.LocationManager;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.sdk.BaseManager;

/* loaded from: classes3.dex */
public final class LastKnownLocationInfoManager extends BaseManager {
    public final LocationManager b;

    public LastKnownLocationInfoManager(Context context) {
        Location lastKnownLocation;
        Location lastKnownLocation2;
        LocationManager locationManager;
        super(context);
        if (a() == null || a() == null) {
            return;
        }
        try {
            this.b = (LocationManager) a().getSystemService("location");
            if (a() == null || (!(a().checkCallingOrSelfPermission("android.permission.ACCESS_COARSE_LOCATION") == 0 || a().checkCallingOrSelfPermission("android.permission.ACCESS_FINE_LOCATION") == 0) || (locationManager = this.b) == null)) {
                lastKnownLocation = null;
                lastKnownLocation2 = null;
            } else {
                lastKnownLocation = locationManager.getLastKnownLocation("gps");
                lastKnownLocation2 = this.b.getLastKnownLocation("network");
            }
            if (lastKnownLocation == null || lastKnownLocation2 == null) {
                return;
            }
            long time = lastKnownLocation2.getTime() - lastKnownLocation.getTime();
            boolean z = time > 120000;
            boolean z2 = time < -120000;
            if (!z && !z2) {
                lastKnownLocation2.getAccuracy();
                lastKnownLocation.getAccuracy();
                String provider = lastKnownLocation2.getProvider();
                String provider2 = lastKnownLocation.getProvider();
                if (provider == null) {
                    return;
                }
                provider.equals(provider2);
            }
        } catch (SecurityException unused) {
            LogUtil.e(5, "LastKnownLocationInfoManager", "Unable to access locationManager due to android firmware bug.");
        }
    }
}
