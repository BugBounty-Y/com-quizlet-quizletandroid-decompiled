package com.pubmatic.sdk.common.models;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;

/* loaded from: classes2.dex */
public class c {
    private String a;
    private String b;
    private String c;

    public c(@NonNull Context context) throws PackageManager.NameNotFoundException {
        try {
            PackageManager packageManager = context.getPackageManager();
            PackageInfo packageInfo = packageManager.getPackageInfo(context.getPackageName(), 0);
            this.a = packageInfo.applicationInfo.loadLabel(packageManager).toString();
            this.b = context.getPackageName();
            this.c = packageInfo.versionName;
        } catch (Exception e) {
            POBLog.error("POBAppInfo", "Failed to retrieve app info: %s", e.getLocalizedMessage());
        }
    }

    public String getAppName() {
        return this.a;
    }

    public String getAppVersion() {
        return this.c;
    }

    public String getPackageName() {
        return this.b;
    }
}
