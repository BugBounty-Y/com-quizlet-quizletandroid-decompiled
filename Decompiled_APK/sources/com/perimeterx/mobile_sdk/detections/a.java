package com.perimeterx.mobile_sdk.detections;

import androidx.compose.material.ripple.r;
import androidx.compose.material3.C0676l1;
import java.util.Date;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final com.perimeterx.mobile_sdk.detections.device.a a;
    public final r b;
    public final C0676l1 c;

    public a(com.perimeterx.mobile_sdk.detections.device.a deviceInfo, r appInfo, C0676l1 usageInfo, Date timestamp) {
        Intrinsics.checkNotNullParameter(deviceInfo, "deviceInfo");
        Intrinsics.checkNotNullParameter(appInfo, "appInfo");
        Intrinsics.checkNotNullParameter(usageInfo, "usageInfo");
        Intrinsics.checkNotNullParameter(timestamp, "timestamp");
        this.a = deviceInfo;
        this.b = appInfo;
        this.c = usageInfo;
    }
}
