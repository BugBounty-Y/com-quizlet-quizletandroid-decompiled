package com.google.firebase.perf.session.gauges;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3692p;
import com.google.android.gms.measurement.internal.Z;
import com.google.firebase.perf.util.Timer;
import com.google.firebase.perf.v1.C3973c;
import com.google.firebase.perf.v1.C3974d;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class f {
    public static final com.google.firebase.perf.logging.a f = com.google.firebase.perf.logging.a.d();
    public final ScheduledExecutorService a;
    public final ConcurrentLinkedQueue b;
    public final Runtime c;
    public ScheduledFuture d;
    public long e;

    public f() {
        ScheduledExecutorService scheduledExecutorServiceNewSingleThreadScheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        Runtime runtime = Runtime.getRuntime();
        this.d = null;
        this.e = -1L;
        this.a = scheduledExecutorServiceNewSingleThreadScheduledExecutor;
        this.b = new ConcurrentLinkedQueue();
        this.c = runtime;
    }

    public final synchronized void a(long j, Timer timer) {
        this.e = j;
        try {
            this.d = this.a.scheduleAtFixedRate(new e(this, timer, 0), 0L, j, TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException e) {
            f.f("Unable to start collecting Memory Metrics: " + e.getMessage());
        }
    }

    public final C3974d b(Timer timer) {
        if (timer == null) {
            return null;
        }
        long jA = timer.a() + timer.a;
        C3973c c3973cY = C3974d.y();
        c3973cY.k();
        C3974d.w((C3974d) c3973cY.b, jA);
        Runtime runtime = this.c;
        int iB = AbstractC3692p.b((Z.b(5) * (runtime.totalMemory() - runtime.freeMemory())) / 1024);
        c3973cY.k();
        C3974d.x((C3974d) c3973cY.b, iB);
        return (C3974d) c3973cY.h();
    }
}
