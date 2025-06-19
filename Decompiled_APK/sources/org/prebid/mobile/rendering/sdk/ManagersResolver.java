package org.prebid.mobile.rendering.sdk;

import android.content.Context;
import org.prebid.mobile.rendering.sdk.deviceData.managers.DeviceInfoImpl;
import org.prebid.mobile.rendering.sdk.deviceData.managers.LastKnownLocationInfoManager;
import org.prebid.mobile.rendering.sdk.deviceData.managers.NetworkConnectionInfoManager;
import org.prebid.mobile.rendering.sdk.deviceData.managers.UserConsentManager;
import org.prebid.mobile.rendering.utils.helpers.Utils;

/* loaded from: classes3.dex */
public class ManagersResolver {
    public DeviceInfoImpl a;
    public LastKnownLocationInfoManager b;
    public NetworkConnectionInfoManager c;
    public UserConsentManager d;

    public static class ManagersResolverHolder {
        public static final ManagersResolver a = new ManagersResolver(0);
    }

    public /* synthetic */ ManagersResolver(int i) {
        this();
    }

    public static ManagersResolver a() {
        return ManagersResolverHolder.a;
    }

    public final void b(Context context) {
        Utils.a = context.getResources().getDisplayMetrics().density;
        if (this.a == null) {
            this.a = new DeviceInfoImpl(context);
        }
        if (this.b == null) {
            this.b = new LastKnownLocationInfoManager(context);
        }
        if (this.c == null) {
            this.c = new NetworkConnectionInfoManager(context);
        }
        if (this.d == null) {
            this.d = new UserConsentManager(context);
        }
    }

    private ManagersResolver() {
    }
}
