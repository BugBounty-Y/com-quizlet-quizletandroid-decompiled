package com.google.android.gms.ads.identifier;

import android.content.Context;
import android.os.SystemClock;
import android.util.Log;
import androidx.compose.foundation.gestures.l1;
import com.google.android.gms.common.internal.MethodInvocation;
import com.google.android.gms.common.internal.TelemetryData;
import com.google.android.gms.common.internal.k;
import com.google.android.gms.common.internal.u;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

/* loaded from: classes2.dex */
public final class d {
    public static volatile d c;
    public static final Object d = new Object();
    public static final Duration e = Duration.ofMinutes(30);
    public final com.google.android.gms.common.internal.service.b a;
    public final AtomicLong b = new AtomicLong(-1);

    public d(Context context) {
        this.a = u.n(context, new k("ads_identifier:api"));
    }

    public final synchronized void a(int i, int i2, long j, long j2) {
        AtomicLong atomicLong = this.b;
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        Log.i("AdvertisingIdClient", "shouldSendLog " + atomicLong.get());
        if (this.b.get() == -1 || jElapsedRealtime - this.b.get() > e.toMillis()) {
            com.google.android.gms.common.internal.service.b bVar = this.a;
            if (bVar != null) {
                bVar.d(new TelemetryData(0, Arrays.asList(new MethodInvocation(35401, i, 0, j, j2, null, null, 0, i2)))).o(new l1(this, jElapsedRealtime, 3));
            }
        }
    }
}
