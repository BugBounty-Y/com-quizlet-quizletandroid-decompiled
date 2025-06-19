package com.braze.requests.util;

import android.os.SystemClock;
import com.braze.U;
import com.braze.requests.framework.o;
import com.braze.support.BrazeLogger;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.random.e;
import kotlin.random.g;

/* loaded from: classes.dex */
public final class b {
    public static final int g = (int) TimeUnit.SECONDS.toMillis(45);
    public final int a;
    public final int b;
    public final int c;
    public final int d;
    public final e e;
    public int f;

    public b(int i, int i2, int i3) {
        int i4 = g;
        this.a = i;
        this.b = i4;
        this.c = i2;
        this.d = i3;
        long jUptimeMillis = SystemClock.uptimeMillis();
        this.e = new g((int) jUptimeMillis, (int) (jUptimeMillis >> 32));
    }

    public final int a(int i) {
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new o(this, 4), 7, (Object) null);
        e random = this.e;
        int i2 = this.f * this.d;
        Intrinsics.checkNotNullParameter(random, "random");
        int iMin = Math.min(i, i2) + random.d(Math.abs(i - i2) + 1);
        this.f = Math.max(this.c, Math.min(this.a, iMin));
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new U(this, i, iMin, 1), 7, (Object) null);
        return this.f;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExponentialBackoffStateProvider(maxSleepDurationMs=");
        sb.append(this.a);
        sb.append(", defaultNormalFlushIntervalMs=");
        sb.append(this.b);
        sb.append(", minSleepDurationMs=");
        sb.append(this.c);
        sb.append(", scaleFactor=");
        sb.append(this.d);
        sb.append(", randomSleepDurationGenerator=");
        sb.append(this.e);
        sb.append(", lastSleepDurationMs=");
        sb.append(this.f);
        sb.append(", isBackingOff=");
        return android.support.v4.media.session.a.u(sb, this.f != 0, ')');
    }

    public static final String a(b bVar) {
        return "Computing new sleep delay. Previous sleep delay: " + bVar.f;
    }

    public static final String a(b bVar, int i, int i2) {
        return "New sleep duration: " + bVar.f + " ms. Default sleep duration: " + i + " ms. Max sleep: " + bVar.a + " ms. Min sleep: " + bVar.c + " ms. Scale factor: " + bVar.d + " randomValueBetweenSleepIntervals: " + i2;
    }
}
