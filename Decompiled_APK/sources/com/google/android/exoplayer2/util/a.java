package com.google.android.exoplayer2.util;

import android.os.Build;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public abstract class a {
    public static final int a;

    static {
        String str = Build.VERSION.CODENAME;
        a = "S".equals(str) ? 31 : "R".equals(str) ? 30 : Build.VERSION.SDK_INT;
        new StringBuilder(String.valueOf(Build.MANUFACTURER).length() + String.valueOf(Build.MODEL).length() + String.valueOf(Build.DEVICE).length() + 17);
        Pattern.compile("(\\d\\d\\d\\d)\\-(\\d\\d)\\-(\\d\\d)[Tt](\\d\\d):(\\d\\d):(\\d\\d)([\\.,](\\d+))?([Zz]|((\\+|\\-)(\\d?\\d):?(\\d\\d)))?");
        Pattern.compile("^(-)?P(([0-9]*)Y)?(([0-9]*)M)?(([0-9]*)D)?(T(([0-9]*)H)?(([0-9]*)M)?(([0-9.]*)S)?)?$");
        Pattern.compile("%([A-Fa-f0-9]{2})");
        Pattern.compile(".*\\.isml?(?:/(manifest(.*))?)?");
    }

    public static boolean a(Object obj, Object obj2) {
        return obj == null ? obj2 == null : obj.equals(obj2);
    }
}
