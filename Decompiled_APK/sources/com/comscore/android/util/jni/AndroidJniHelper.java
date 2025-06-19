package com.comscore.android.util.jni;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.text.TextUtils;
import com.amazon.device.ads.DtbConstants;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.comscore.BuildConfig;
import com.comscore.android.CommonUtils;
import com.comscore.android.ConnectivityType;
import com.comscore.android.HostApplicationState;
import com.comscore.android.id.CrossPublisherId;
import com.comscore.android.id.DeviceId;
import com.comscore.android.id.IdHelperAndroid;
import com.comscore.android.util.AndroidTcfDataLoader;
import com.comscore.android.util.BackgroundManager;
import com.comscore.android.util.Permissions;
import com.comscore.android.util.update.UpdateFrom5_4_x;
import com.comscore.util.CrossPublisherIdUtil;
import com.comscore.util.TcfDataLoader;
import com.comscore.util.crashreport.CrashReportDecorator;
import com.comscore.util.jni.JniComScoreHelper;
import com.comscore.util.log.Logger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/* loaded from: classes.dex */
public class AndroidJniHelper extends JniComScoreHelper {
    public static final String KEY_PACKAGE_MANAGER = "packageManager";
    private Context b;
    private BackgroundManager c;
    private UpdateFrom5_4_x d;
    private int e = -1;
    private int f = -1;
    private AndroidTcfDataLoader g = new AndroidTcfDataLoader();

    private int a(int i) {
        if (i != 1) {
            return i != 2 ? 0 : 1;
        }
        return 2;
    }

    private static native void setContextNative(Context context);

    @Override // com.comscore.util.jni.JniComScoreHelper
    public CrashReportDecorator createCrashReportDecorator() {
        return new AndroidCrashReportDecorator(this);
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getAppDataDir() {
        Context context = this.b;
        if (context == null) {
            return null;
        }
        return context.getFilesDir().getAbsolutePath();
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getApplicationId() {
        Context context = this.b;
        if (context == null) {
            return null;
        }
        return context.getPackageName();
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getApplicationName() {
        Context context = this.b;
        if (context == null) {
            return null;
        }
        return CommonUtils.getApplicationName(context);
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getApplicationVersion() {
        return CommonUtils.getApplicationVersion(this.b);
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getArchitecture() {
        return CommonUtils.getDeviceArchitecture();
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public int getConnectivityType() {
        Context context = this.b;
        return context == null ? ConnectivityType.UNKNOWN : CommonUtils.getConnectivityType(context);
    }

    public Context getContext() {
        return this.b;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getCrossPublisherUniqueDeviceId() {
        Context context = this.b;
        if (context == null) {
            return null;
        }
        CrossPublisherId crossPublisherDeviceId = IdHelperAndroid.getCrossPublisherDeviceId(context);
        StringBuilder sb = new StringBuilder();
        String str = crossPublisherDeviceId.crossPublisherId;
        if (str == null) {
            str = "";
        }
        sb.append(str);
        sb.append(" ");
        sb.append(crossPublisherDeviceId.source);
        return sb.toString();
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public int getCurrentHostApplicationState() {
        int state = HostApplicationState.getState(this.b);
        if (state == -1) {
            state = 1;
        }
        if (this.e == -1) {
            if (state == 0) {
                this.e = 1;
                return state;
            }
            this.e = 2;
        }
        return state;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String[] getDeviceIds() {
        DeviceId deviceId = IdHelperAndroid.getDeviceId(this.b);
        return new String[]{deviceId.getId() + " " + deviceId.getCommonness() + "" + deviceId.getPersistency() + " true " + deviceId.getSource() + " " + a(deviceId.getSource())};
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getDeviceModel() {
        return CommonUtils.getDeviceModel();
    }

    public int getFirstHostState() {
        return this.e;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String[] getInvalidIds() {
        return IdHelperAndroid.INVALID_ID_VALUES;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getLanguage() {
        return CommonUtils.getLanguage();
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getOsName() {
        return DtbConstants.NATIVE_OS_NAME;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getOsVersion() {
        return CommonUtils.getOsVersion();
    }

    public String getPackageManagerName() {
        Context context = this.b;
        if (context == null) {
            return DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        }
        try {
            String initiatingPackageName = Build.VERSION.SDK_INT >= 30 ? context.getPackageManager().getInstallSourceInfo(this.b.getPackageName()).getInitiatingPackageName() : context.getPackageManager().getInstallerPackageName(this.b.getPackageName());
            return !TextUtils.isEmpty(initiatingPackageName) ? initiatingPackageName : DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        } catch (PackageManager.NameNotFoundException unused) {
            return DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        }
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getPlatformEnvironmentProperties(String str) {
        return String.format(Locale.getDefault(), "%d-%s-%d%d%d-%d-%d", Integer.valueOf(IdHelperAndroid.getCrossPublisherDeviceId(this.b).source), str, Integer.valueOf(Permissions.check(this.b, "android.permission.INTERNET").booleanValue() ? 1 : 0), Integer.valueOf(Permissions.check(this.b, "android.permission.ACCESS_NETWORK_STATE").booleanValue() ? 1 : 0), Integer.valueOf(Permissions.check(this.b, "android.permission.ACCESS_WIFI_STATE").booleanValue() ? 1 : 0), Integer.valueOf(isLibraryInstalledUsingMaven() ? 1 : 0), Integer.valueOf(this.e));
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public Map<String, String> getPlatformLabels(Map<String, String> map) {
        if (this.b == null) {
            return null;
        }
        HashMap map2 = new HashMap();
        int i = IdHelperAndroid.getCrossPublisherDeviceId(this.b).source;
        map2.put("ns_ap_res", CommonUtils.getApplicationResolution(this.b));
        if (i == 1 && !TextUtils.isEmpty(map.get("ns_ak"))) {
            String mD5CrossPublisherDeviceId = CrossPublisherIdUtil.getMD5CrossPublisherDeviceId();
            if (!TextUtils.isEmpty(mD5CrossPublisherDeviceId)) {
                map2.put("ns_ap_i3", mD5CrossPublisherDeviceId);
            }
        }
        if (TextUtils.isEmpty(map.get("ns_ap_an"))) {
            map2.put("ns_ap_an", getApplicationName());
        }
        if (TextUtils.isEmpty(map.get("ns_ap_ver"))) {
            map2.put("ns_ap_ver", getApplicationVersion());
        }
        if (TextUtils.isEmpty(map.get("ns_ap_bi"))) {
            map2.put("ns_ap_bi", getApplicationId());
        }
        map2.put("ns_ap_ais", getPackageManagerName());
        return map2;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getRuntimeName() {
        return DtbConstants.NATIVE_OS_NAME;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public String getRuntimeVersion() {
        return getOsVersion();
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public int getScreenHeight() {
        Context context = this.b;
        if (context == null) {
            return 0;
        }
        return CommonUtils.getDisplaySize(context).y;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public int getScreenWidth() {
        Context context = this.b;
        if (context == null) {
            return 0;
        }
        return CommonUtils.getDisplaySize(context).x;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public TcfDataLoader getTcfDataLoader() {
        return this.g;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public boolean isJailBroken() {
        return CommonUtils.isDeviceRooted();
    }

    public boolean isLibraryInstalledUsingMaven() {
        if (this.f == -1) {
            try {
                this.f = ((String) BuildConfig.class.getField("FLAVOR").get(null)).startsWith(BuildConfig.FLAVOR) ? 1 : 0;
            } catch (Exception unused) {
                this.f = 0;
            }
        }
        return this.f == 1;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public boolean libraryPostUpdate(String str, String str2, Map<String, String> map, ArrayList<String> arrayList) throws Throwable {
        UpdateFrom5_4_x updateFrom5_4_x = this.d;
        if (updateFrom5_4_x == null) {
            return false;
        }
        updateFrom5_4_x.libraryPostUpdate(map, arrayList);
        return true;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public boolean libraryUpdate(String str, String str2, Map<String, String> map) {
        if ((str != null && str.length() != 0) || map.containsKey("updated_from_versions")) {
            return false;
        }
        UpdateFrom5_4_x updateFrom5_4_x = new UpdateFrom5_4_x(this.b);
        this.d = updateFrom5_4_x;
        updateFrom5_4_x.libraryUpdate(map);
        return true;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public void onCoreStarted() {
        super.onCoreStarted();
        this.g.setContext(this.b);
    }

    public void setContext(Context context) {
        if (context == null) {
            throw new NullPointerException("The Context parameter provided cannot be null.");
        }
        Context applicationContext = context.getApplicationContext();
        this.b = applicationContext;
        if (applicationContext == null) {
            throw new NullPointerException("The Context provided by context.getApplicationContext() cannot be null.");
        }
        setContextNative(applicationContext);
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public boolean subscribeToForegroundNotification() {
        Context context = this.b;
        if (!(context instanceof Application)) {
            Logger.w("Unable to detect automatically if the application is in the foreground or in the background.");
            return false;
        }
        BackgroundManager backgroundManager = new BackgroundManager((Application) context);
        this.c = backgroundManager;
        backgroundManager.register();
        return true;
    }

    @Override // com.comscore.util.jni.JniComScoreHelper
    public boolean unsubscribeFromForegroundNotification() {
        BackgroundManager backgroundManager = this.c;
        if (backgroundManager == null) {
            return false;
        }
        backgroundManager.unregister();
        return true;
    }
}
