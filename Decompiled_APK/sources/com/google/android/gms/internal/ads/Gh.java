package com.google.android.gms.internal.ads;

import java.util.Collections;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class Gh extends AbstractC2863yB {
    public final ScheduledExecutorService c;
    public final com.google.android.gms.common.util.a d;
    public long e;
    public long f;
    public long g;
    public long h;
    public boolean i;
    public ScheduledFuture j;
    public ScheduledFuture k;

    public Gh(ScheduledExecutorService scheduledExecutorService, com.google.android.gms.common.util.a aVar) {
        super(Collections.EMPTY_SET);
        this.e = -1L;
        this.f = -1L;
        this.g = -1L;
        this.h = -1L;
        this.i = false;
        this.c = scheduledExecutorService;
        this.d = aVar;
    }

    public final synchronized void a() {
        this.i = false;
        m1(0L);
    }

    public final synchronized void k1(int i) {
        com.google.android.gms.ads.internal.util.A.l("In scheduleRefresh: " + i);
        if (i > 0) {
            long millis = TimeUnit.SECONDS.toMillis(i);
            if (this.i) {
                long j = this.g;
                if (j <= 0 || millis >= j) {
                    millis = j;
                }
                this.g = millis;
                return;
            }
            long jElapsedRealtime = this.d.elapsedRealtime();
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.gd)).booleanValue()) {
                long j2 = this.e;
                if (jElapsedRealtime >= j2 || j2 - jElapsedRealtime > millis) {
                    m1(millis);
                }
            } else {
                long j3 = this.e;
                if (jElapsedRealtime > j3 || j3 - jElapsedRealtime > millis) {
                    m1(millis);
                }
            }
        }
    }

    public final synchronized void l1(int i) {
        com.google.android.gms.ads.internal.util.A.l("In scheduleShowRefreshedAd: " + i);
        if (i > 0) {
            long millis = TimeUnit.SECONDS.toMillis(i);
            if (this.i) {
                long j = this.h;
                if (j <= 0 || millis >= j) {
                    millis = j;
                }
                this.h = millis;
                return;
            }
            long jElapsedRealtime = this.d.elapsedRealtime();
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.gd)).booleanValue()) {
                if (jElapsedRealtime == this.f) {
                    com.google.android.gms.ads.internal.util.A.l("In scheduleShowRefreshedAd: currentTimeMs = scheduledShowTimeMs");
                }
                long j2 = this.f;
                if (jElapsedRealtime >= j2 || j2 - jElapsedRealtime > millis) {
                    n1(millis);
                }
            } else {
                long j3 = this.f;
                if (jElapsedRealtime > j3 || j3 - jElapsedRealtime > millis) {
                    n1(millis);
                }
            }
        }
    }

    public final synchronized void m1(long j) {
        try {
            ScheduledFuture scheduledFuture = this.j;
            if (scheduledFuture != null && !scheduledFuture.isDone()) {
                this.j.cancel(false);
            }
            this.e = this.d.elapsedRealtime() + j;
            this.j = this.c.schedule(new Fh(this, 0), j, TimeUnit.MILLISECONDS);
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void n1(long j) {
        try {
            ScheduledFuture scheduledFuture = this.k;
            if (scheduledFuture != null && !scheduledFuture.isDone()) {
                this.k.cancel(false);
            }
            this.f = this.d.elapsedRealtime() + j;
            this.k = this.c.schedule(new Fh(this, 1), j, TimeUnit.MILLISECONDS);
        } catch (Throwable th) {
            throw th;
        }
    }
}
