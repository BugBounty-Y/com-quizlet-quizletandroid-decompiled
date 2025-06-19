package org.prebid.mobile.rendering.sdk.deviceData.managers;

import android.content.Context;
import android.content.pm.PackageManager;
import android.telephony.TelephonyManager;
import android.view.WindowManager;
import org.prebid.mobile.rendering.sdk.BaseManager;

/* loaded from: classes3.dex */
public class DeviceInfoImpl extends BaseManager {
    public final TelephonyManager b;
    public final WindowManager c;

    public DeviceInfoImpl(Context context) {
        super(context);
        if (context != null) {
            TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
            this.b = telephonyManager;
            this.c = (WindowManager) context.getSystemService("window");
            PackageManager packageManager = context.getPackageManager();
            if (telephonyManager == null || packageManager == null) {
                return;
            }
            packageManager.hasSystemFeature("android.hardware.telephony");
        }
    }
}
