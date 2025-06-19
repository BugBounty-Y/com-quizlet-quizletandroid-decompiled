package com.braze.requests.util;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.support.DateTimeUtils;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final SharedPreferences a;

    public a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("persistent.com.braze.requests.metadata.last_req_at", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        this.a = sharedPreferences;
    }

    public final long a(c target) {
        Intrinsics.checkNotNullParameter(target, "target");
        String str = "uri-" + target.a.hashCode();
        long j = this.a.getLong(str, 0L);
        long jNowInMilliseconds = DateTimeUtils.nowInMilliseconds();
        this.a.edit().putLong(str, jNowInMilliseconds).apply();
        return Math.min(jNowInMilliseconds - j, 7200000L);
    }

    public final long b(c target) {
        Intrinsics.checkNotNullParameter(target, "target");
        String str = "uri-at-" + target.a.hashCode();
        long j = this.a.getLong(str, 1L);
        this.a.edit().putLong(str, 1 + j).apply();
        return j;
    }

    public final void c(c target) {
        Intrinsics.checkNotNullParameter(target, "target");
        this.a.edit().putLong("uri-at-" + target.a.hashCode(), 1L).apply();
    }
}
