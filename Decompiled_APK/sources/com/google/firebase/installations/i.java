package com.google.firebase.installations;

import android.text.TextUtils;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class i {
    public static final long b = TimeUnit.HOURS.toSeconds(1);
    public static final Pattern c = Pattern.compile("\\AA[\\w-]{38}\\z");
    public static i d;
    public final retrofit2.adapter.rxjava3.d a;

    public i(retrofit2.adapter.rxjava3.d dVar) {
        this.a = dVar;
    }

    public final boolean a(com.google.firebase.installations.local.a aVar) {
        if (TextUtils.isEmpty(aVar.c)) {
            return true;
        }
        long j = aVar.f + aVar.e;
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        this.a.getClass();
        return j < timeUnit.toSeconds(System.currentTimeMillis()) + b;
    }
}
