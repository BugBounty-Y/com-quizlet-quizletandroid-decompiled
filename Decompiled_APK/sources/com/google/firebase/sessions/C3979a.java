package com.google.firebase.sessions;

import android.os.Build;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.firebase.sessions.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3979a {
    public final String a;
    public final String b;
    public final String c;
    public final D d;
    public final ArrayList e;

    public C3979a(String packageName, String versionName, String appBuildVersion, D currentProcessDetails, ArrayList appProcessDetails) {
        String deviceManufacturer = Build.MANUFACTURER;
        Intrinsics.checkNotNullParameter(packageName, "packageName");
        Intrinsics.checkNotNullParameter(versionName, "versionName");
        Intrinsics.checkNotNullParameter(appBuildVersion, "appBuildVersion");
        Intrinsics.checkNotNullParameter(deviceManufacturer, "deviceManufacturer");
        Intrinsics.checkNotNullParameter(currentProcessDetails, "currentProcessDetails");
        Intrinsics.checkNotNullParameter(appProcessDetails, "appProcessDetails");
        this.a = packageName;
        this.b = versionName;
        this.c = appBuildVersion;
        this.d = currentProcessDetails;
        this.e = appProcessDetails;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C3979a)) {
            return false;
        }
        C3979a c3979a = (C3979a) obj;
        if (!Intrinsics.b(this.a, c3979a.a) || !Intrinsics.b(this.b, c3979a.b) || !Intrinsics.b(this.c, c3979a.c)) {
            return false;
        }
        String str = Build.MANUFACTURER;
        return Intrinsics.b(str, str) && this.d.equals(c3979a.d) && this.e.equals(c3979a.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, Build.MANUFACTURER)) * 31);
    }

    public final String toString() {
        return "AndroidApplicationInfo(packageName=" + this.a + ", versionName=" + this.b + ", appBuildVersion=" + this.c + ", deviceManufacturer=" + Build.MANUFACTURER + ", currentProcessDetails=" + this.d + ", appProcessDetails=" + this.e + ')';
    }
}
