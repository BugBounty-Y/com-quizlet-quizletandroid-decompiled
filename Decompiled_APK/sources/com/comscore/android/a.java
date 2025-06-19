package com.comscore.android;

import android.content.Context;

/* loaded from: classes.dex */
class a {
    private static String[] a;

    public static Boolean a(Context context, String str) {
        Boolean bool = Boolean.FALSE;
        if (a == null) {
            try {
                a = context.getPackageManager().getPackageInfo(context.getPackageName(), 4096).requestedPermissions;
            } catch (Exception unused) {
            }
        }
        if (a == null) {
            return bool;
        }
        int i = 0;
        while (true) {
            String[] strArr = a;
            if (i >= strArr.length) {
                return bool;
            }
            if (strArr[i].equals(str)) {
                return Boolean.TRUE;
            }
            i++;
        }
    }
}
