package org.prebid.mobile.rendering.networking.parameters;

import android.telephony.TelephonyManager;
import org.prebid.mobile.rendering.sdk.ManagersResolver;
import org.prebid.mobile.rendering.sdk.deviceData.managers.DeviceInfoImpl;
import org.prebid.mobile.rendering.sdk.deviceData.managers.NetworkConnectionInfoManager;
import org.prebid.mobile.rendering.utils.helpers.Utils;

/* loaded from: classes3.dex */
public class NetworkParameterBuilder extends ParameterBuilder {
    @Override // org.prebid.mobile.rendering.networking.parameters.ParameterBuilder
    public final void a(AdRequestInput adRequestInput) {
        String str;
        String networkOperator;
        DeviceInfoImpl deviceInfoImpl = ManagersResolver.a().a;
        if (deviceInfoImpl != null) {
            TelephonyManager telephonyManager = deviceInfoImpl.b;
            if (telephonyManager == null || (networkOperator = telephonyManager.getNetworkOperator()) == null || networkOperator.equals("") || networkOperator.length() <= 3) {
                str = null;
            } else {
                str = networkOperator.substring(0, 3) + '-' + networkOperator.substring(3);
            }
            if (Utils.c(str)) {
                adRequestInput.a.a().k = str;
            }
            String networkOperatorName = telephonyManager != null ? telephonyManager.getNetworkOperatorName() : null;
            if (Utils.c(networkOperatorName)) {
                adRequestInput.a.a().j = networkOperatorName;
            }
        }
        NetworkConnectionInfoManager networkConnectionInfoManager = ManagersResolver.a().c;
        if (networkConnectionInfoManager == null || deviceInfoImpl == null || deviceInfoImpl.a() == null || deviceInfoImpl.a().checkCallingOrSelfPermission("android.permission.ACCESS_NETWORK_STATE") != 0) {
            return;
        }
        int iOrdinal = networkConnectionInfoManager.b().ordinal();
        if (iOrdinal == 1) {
            adRequestInput.a.a().o = 2;
        } else {
            if (iOrdinal != 2) {
                return;
            }
            adRequestInput.a.a().o = 3;
        }
    }
}
