package org.prebid.mobile.rendering.networking.parameters;

import org.prebid.mobile.PrebidMobile;
import org.prebid.mobile.rendering.sdk.ManagersResolver;
import org.prebid.mobile.rendering.sdk.deviceData.managers.DeviceInfoImpl;
import org.prebid.mobile.rendering.sdk.deviceData.managers.LastKnownLocationInfoManager;

/* loaded from: classes3.dex */
public class GeoLocationParameterBuilder extends ParameterBuilder {
    @Override // org.prebid.mobile.rendering.networking.parameters.ParameterBuilder
    public final void a(AdRequestInput adRequestInput) {
        LastKnownLocationInfoManager lastKnownLocationInfoManager = ManagersResolver.a().b;
        DeviceInfoImpl deviceInfoImpl = ManagersResolver.a().a;
        adRequestInput.a.a().getClass();
        if (lastKnownLocationInfoManager != null) {
            int i = PrebidMobile.a;
        }
    }
}
