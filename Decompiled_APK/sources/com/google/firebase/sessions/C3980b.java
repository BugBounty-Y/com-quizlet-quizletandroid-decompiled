package com.google.firebase.sessions;

import android.os.Build;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.firebase.sessions.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3980b {
    public final String a;
    public final C3979a b;

    public C3980b(String appId, C3979a androidAppInfo) {
        String deviceModel = Build.MODEL;
        String osVersion = Build.VERSION.RELEASE;
        C logEnvironment = C.LOG_ENVIRONMENT_PROD;
        Intrinsics.checkNotNullParameter(appId, "appId");
        Intrinsics.checkNotNullParameter(deviceModel, "deviceModel");
        Intrinsics.checkNotNullParameter("2.1.1", "sessionSdkVersion");
        Intrinsics.checkNotNullParameter(osVersion, "osVersion");
        Intrinsics.checkNotNullParameter(logEnvironment, "logEnvironment");
        Intrinsics.checkNotNullParameter(androidAppInfo, "androidAppInfo");
        this.a = appId;
        this.b = androidAppInfo;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C3980b)) {
            return false;
        }
        C3980b c3980b = (C3980b) obj;
        if (!Intrinsics.b(this.a, c3980b.a)) {
            return false;
        }
        String str = Build.MODEL;
        if (!Intrinsics.b(str, str)) {
            return false;
        }
        String str2 = Build.VERSION.RELEASE;
        return Intrinsics.b(str2, str2) && this.b.equals(c3980b.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + ((C.LOG_ENVIRONMENT_PROD.hashCode() + androidx.compose.animation.d0.e((((Build.MODEL.hashCode() + (this.a.hashCode() * 31)) * 31) + 47595000) * 31, 31, Build.VERSION.RELEASE)) * 31);
    }

    public final String toString() {
        return "ApplicationInfo(appId=" + this.a + ", deviceModel=" + Build.MODEL + ", sessionSdkVersion=2.1.1, osVersion=" + Build.VERSION.RELEASE + ", logEnvironment=" + C.LOG_ENVIRONMENT_PROD + ", androidAppInfo=" + this.b + ')';
    }
}
