package org.prebid.mobile.rendering.networking.parameters;

import android.graphics.Point;
import android.os.Build;
import android.view.WindowManager;
import com.quizlet.quizletandroid.R;
import java.util.Locale;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.configuration.AdUnitConfiguration;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.Device;
import org.prebid.mobile.rendering.sdk.ManagersResolver;
import org.prebid.mobile.rendering.sdk.deviceData.managers.DeviceInfoImpl;
import org.prebid.mobile.rendering.sdk.deviceData.managers.UserConsentManager;
import org.prebid.mobile.rendering.utils.helpers.AdvertisingIdManager;
import org.prebid.mobile.rendering.utils.helpers.AppInfoManager;
import org.prebid.mobile.rendering.utils.helpers.Utils;

/* loaded from: classes3.dex */
public class DeviceInfoParameterBuilder extends ParameterBuilder {
    public AdUnitConfiguration a;

    @Override // org.prebid.mobile.rendering.networking.parameters.ParameterBuilder
    public final void a(AdRequestInput adRequestInput) {
        int i;
        int i2;
        DeviceInfoImpl deviceInfoImpl = ManagersResolver.a().a;
        if (deviceInfoImpl != null) {
            WindowManager windowManager = deviceInfoImpl.c;
            int i3 = 0;
            if (windowManager != null) {
                Point point = new Point();
                windowManager.getDefaultDisplay().getRealSize(point);
                i = point.x;
            } else {
                i = 0;
            }
            WindowManager windowManager2 = deviceInfoImpl.c;
            if (windowManager2 != null) {
                Point point2 = new Point();
                windowManager2.getDefaultDisplay().getRealSize(point2);
                i2 = point2.y;
            } else {
                i2 = 0;
            }
            Device deviceA = adRequestInput.a.a();
            deviceA.p = Float.valueOf(Utils.a);
            if (i > 0 && i2 > 0) {
                deviceA.n = Integer.valueOf(i);
                deviceA.m = Integer.valueOf(i2);
            }
            UserConsentManager userConsentManager = ManagersResolver.a().d;
            String str = null;
            if (userConsentManager == null) {
                LogUtil.e(5, "AdvertisingIdManager", "Can't get advertising id. UserConsentManager is null.");
            } else {
                int i4 = userConsentManager.b;
                Boolean bool = null;
                boolean zEquals = true;
                Boolean bool2 = i4 == 0 ? Boolean.FALSE : i4 == 1 ? Boolean.TRUE : null;
                String str2 = userConsentManager.d;
                if (str2 != null && str2.length() > 0) {
                    char cCharAt = str2.charAt(0);
                    if (cCharAt == '1') {
                        bool = Boolean.TRUE;
                    } else if (cCharAt == '0') {
                        bool = Boolean.FALSE;
                    } else {
                        LogUtil.e(5, "PrebidMobile", "Can't get GDPR purpose consent, unsupported char: " + cCharAt);
                    }
                }
                if ((bool != null || bool2 != null) && (bool != null || !Boolean.FALSE.equals(bool2))) {
                    zEquals = Boolean.TRUE.equals(bool);
                }
                if (zEquals && AdvertisingIdManager.b != null) {
                    str = AdvertisingIdManager.b.a;
                }
            }
            if (Utils.c(str)) {
                deviceA.l = str;
            }
            if (deviceInfoImpl.a() != null ? deviceInfoImpl.a().getResources().getBoolean(R.bool.prebid_is_tablet) : false) {
                deviceA.c = 5;
            } else {
                deviceA.c = 4;
            }
            deviceA.d = Build.MANUFACTURER;
            deviceA.e = Build.MODEL;
            deviceA.f = "Android";
            deviceA.g = Build.VERSION.RELEASE;
            deviceA.i = Locale.getDefault().getLanguage();
            deviceA.a = AppInfoManager.a;
            if (AdvertisingIdManager.b != null && AdvertisingIdManager.b.b) {
                i3 = 1;
            }
            deviceA.b = Integer.valueOf(i3);
            this.a.getClass();
        }
    }
}
