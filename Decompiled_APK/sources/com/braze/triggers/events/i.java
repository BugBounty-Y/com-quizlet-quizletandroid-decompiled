package com.braze.triggers.events;

import android.util.Base64;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.StringUtils;

/* loaded from: classes.dex */
public abstract class i implements b {
    public static final String d = BrazeLogger.getBrazeLogTag((Class<?>) i.class);
    public final long a;
    public final long b;
    public com.braze.models.i c;

    public i() {
        long jNowInMilliseconds = DateTimeUtils.nowInMilliseconds();
        this.b = jNowInMilliseconds;
        this.a = jNowInMilliseconds / 1000;
    }

    public static String a(String str) {
        if (StringUtils.isNullOrBlank(str)) {
            return null;
        }
        try {
            return new String(Base64.decode(str, 0)).split("_")[0];
        } catch (Exception e) {
            BrazeLogger.e(d, "Unexpected error decoding Base64 encoded campaign Id " + str, e);
            return null;
        }
    }
}
