package com.google.android.gms.internal.mlkit_vision_common;

import android.os.SystemClock;
import java.io.Closeable;
import java.util.HashMap;
import java.util.Locale;

/* loaded from: classes2.dex */
public class G4 implements Closeable, AutoCloseable {
    public static final HashMap f = new HashMap();
    public int a;
    public long b;
    public long c;
    public long d = 2147483647L;
    public long e = -2147483648L;

    public G4(String str) {
    }

    public void a() {
        this.b = SystemClock.elapsedRealtimeNanos() / 1000;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        long j = this.b;
        if (j == 0) {
            throw new IllegalStateException("Did you forget to call start()?");
        }
        f(j);
    }

    public void d(long j) {
        long jElapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos() / 1000;
        long j2 = this.c;
        if (j2 != 0 && jElapsedRealtimeNanos - j2 >= 1000000) {
            this.a = 0;
            this.b = 0L;
            this.d = 2147483647L;
            this.e = -2147483648L;
        }
        this.c = jElapsedRealtimeNanos;
        this.a++;
        this.d = Math.min(this.d, j);
        this.e = Math.max(this.e, j);
        if (this.a % 50 == 0) {
            Locale locale = Locale.US;
            O4.b();
        }
        if (this.a % com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR == 0) {
            this.a = 0;
            this.b = 0L;
            this.d = 2147483647L;
            this.e = -2147483648L;
        }
    }

    public void f(long j) {
        d((SystemClock.elapsedRealtimeNanos() / 1000) - j);
    }
}
