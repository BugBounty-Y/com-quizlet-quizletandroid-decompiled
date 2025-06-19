package com.perimeterx.mobile_sdk.configurations;

import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;

/* loaded from: classes2.dex */
public abstract class i {
    public static final String a;
    public static final String[] b;

    static {
        d[] dVarArr = d.a;
        if (c.a[0] != 1) {
            throw new NoWhenBranchMatchedException();
        }
        a = "UTF-8";
        b = new String[]{"/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su"};
    }

    public static String a(String format, String value) {
        Intrinsics.checkNotNullParameter(format, "format");
        Intrinsics.checkNotNullParameter(value, "value");
        return D.o(format, "%@", value, false);
    }
}
