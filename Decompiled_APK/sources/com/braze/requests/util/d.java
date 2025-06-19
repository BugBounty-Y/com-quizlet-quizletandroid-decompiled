package com.braze.requests.util;

import android.content.SharedPreferences;
import androidx.compose.animation.d0;
import com.braze.managers.J;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d {
    public int a;
    public int b;
    public final SharedPreferences c;
    public long d;
    public double e;

    public d(int i, int i2, SharedPreferences storage) {
        Intrinsics.checkNotNullParameter(storage, "storage");
        this.a = i;
        this.b = i2;
        this.c = storage;
        this.d = storage.getLong("last_call_at_ms", 0L);
        this.e = storage.getFloat("current_token_count", this.a < 1 ? 1 : r3);
    }

    public final void a() {
        long jNowInMillisecondsSystemClock = DateTimeUtils.nowInMillisecondsSystemClock();
        this.e = a(jNowInMillisecondsSystemClock);
        this.d = jNowInMillisecondsSystemClock;
        this.c.edit().putLong("last_call_at_ms", this.d).putFloat("current_token_count", (float) this.e).apply();
        double d = this.e;
        if (d < 1.0d) {
            return;
        }
        this.e = d - 1;
    }

    public final long b() {
        this.e = a(DateTimeUtils.nowInMillisecondsSystemClock());
        this.c.edit().putLong("last_call_at_ms", this.d).putFloat("current_token_count", (float) this.e).apply();
        double d = this.e;
        if (d >= 1.0d) {
            return 0L;
        }
        return Math.max(0L, (long) ((1 - d) * (this.b >= 1 ? r0 : 1) * 1000));
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("(capacity=");
        int i = this.a;
        if (i < 1) {
            i = 1;
        }
        sb.append(i);
        sb.append(", refillRate=");
        sb.append(this.b >= 1 ? r1 : 1);
        sb.append(", lastCallAt='");
        sb.append(DateTimeUtils.formatDateFromMillis$default(this.d, null, null, 3, null));
        sb.append("', currentTokenCount=");
        sb.append(a(DateTimeUtils.nowInMillisecondsSystemClock()));
        sb.append(')');
        return sb.toString();
    }

    public static final String b(int i, int i2) {
        return d0.p("TokenBucketRateLimiter updated with new capacity: ", i, " and refill rate: ", i2);
    }

    public final double a(long j) {
        double d = this.e;
        double d2 = j - this.d;
        int i = this.b;
        if (i < 1) {
            i = 1;
        }
        return Math.min(((d2 / i) / 1000) + d, this.a >= 1 ? r0 : 1);
    }

    public final void a(int i, int i2) {
        if (i < 1 || i2 < 1) {
            return;
        }
        if (this.a == i && this.b == i2) {
            return;
        }
        this.a = i;
        this.b = i2;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new J(i, i2, 1), 6, (Object) null);
    }
}
