package com.braze;

import android.os.Build;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class Constants {
    public static final Constants INSTANCE = new Constants();
    private static final boolean isAmazonDevice = "Amazon".equals(Build.MANUFACTURER);

    private Constants() {
    }

    public static final boolean isAmazonDevice() {
        return isAmazonDevice;
    }
}
