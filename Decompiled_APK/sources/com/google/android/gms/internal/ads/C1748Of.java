package com.google.android.gms.internal.ads;

import android.os.SystemClock;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.Of, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1748Of implements L5 {
    public final ScheduledExecutorService a;
    public final com.google.android.gms.common.util.b b;
    public ScheduledFuture c;
    public long d = -1;
    public long e = -1;
    public RunnableC2497pp f = null;
    public boolean g = false;

    public C1748Of(ScheduledExecutorService scheduledExecutorService, com.google.android.gms.common.util.b bVar) {
        this.a = scheduledExecutorService;
        this.b = bVar;
        com.google.android.gms.ads.internal.j.C.g.l(this);
    }

    @Override // com.google.android.gms.internal.ads.L5
    public final void V(boolean z) {
        ScheduledFuture scheduledFuture;
        if (z) {
            synchronized (this) {
                try {
                    if (this.g) {
                        if (this.e > 0 && (scheduledFuture = this.c) != null && scheduledFuture.isCancelled()) {
                            this.c = this.a.schedule(this.f, this.e, TimeUnit.MILLISECONDS);
                        }
                        this.g = false;
                        return;
                    }
                    return;
                } finally {
                }
            }
        }
        synchronized (this) {
            try {
                if (this.g) {
                    return;
                }
                ScheduledFuture scheduledFuture2 = this.c;
                if (scheduledFuture2 == null || scheduledFuture2.isDone()) {
                    this.e = -1L;
                } else {
                    this.c.cancel(true);
                    long j = this.d;
                    this.b.getClass();
                    this.e = j - SystemClock.elapsedRealtime();
                }
                this.g = true;
            } finally {
            }
        }
    }
}
