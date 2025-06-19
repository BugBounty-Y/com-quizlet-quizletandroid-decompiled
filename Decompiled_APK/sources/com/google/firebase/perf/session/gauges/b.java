package com.google.firebase.perf.session.gauges;

import android.os.Process;
import android.system.Os;
import android.system.OsConstants;
import com.google.firebase.perf.util.Timer;
import com.google.firebase.perf.v1.j;
import com.google.firebase.perf.v1.k;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class b {
    public static final com.google.firebase.perf.logging.a g = com.google.firebase.perf.logging.a.d();
    public static final long h = TimeUnit.SECONDS.toMicros(1);
    public ScheduledFuture e = null;
    public long f = -1;
    public final ConcurrentLinkedQueue a = new ConcurrentLinkedQueue();
    public final ScheduledExecutorService b = Executors.newSingleThreadScheduledExecutor();
    public final String c = "/proc/" + Integer.toString(Process.myPid()) + "/stat";
    public final long d = Os.sysconf(OsConstants._SC_CLK_TCK);

    public final synchronized void a(long j, Timer timer) {
        this.f = j;
        try {
            this.e = this.b.scheduleAtFixedRate(new a(this, timer, 0), 0L, j, TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException e) {
            g.f("Unable to start collecting Cpu Metrics: " + e.getMessage());
        }
    }

    public final k b(Timer timer) {
        long j = this.d;
        com.google.firebase.perf.logging.a aVar = g;
        if (timer == null) {
            return null;
        }
        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(this.c));
            try {
                long jA = timer.a() + timer.a;
                String[] strArrSplit = bufferedReader.readLine().split(" ");
                long j2 = Long.parseLong(strArrSplit[13]);
                long j3 = Long.parseLong(strArrSplit[15]);
                long j4 = Long.parseLong(strArrSplit[14]);
                long j5 = Long.parseLong(strArrSplit[16]);
                j jVarZ = k.z();
                jVarZ.k();
                k.w((k) jVarZ.b, jA);
                double d = (j4 + j5) / j;
                long j6 = h;
                long jRound = Math.round(d * j6);
                jVarZ.k();
                k.y((k) jVarZ.b, jRound);
                long jRound2 = Math.round(((j2 + j3) / j) * j6);
                jVarZ.k();
                k.x((k) jVarZ.b, jRound2);
                k kVar = (k) jVarZ.h();
                bufferedReader.close();
                return kVar;
            } finally {
            }
        } catch (IOException e) {
            aVar.f("Unable to read 'proc/[pid]/stat' file: " + e.getMessage());
            return null;
        } catch (ArrayIndexOutOfBoundsException e2) {
            e = e2;
            aVar.f("Unexpected '/proc/[pid]/stat' file format encountered: " + e.getMessage());
            return null;
        } catch (NullPointerException e3) {
            e = e3;
            aVar.f("Unexpected '/proc/[pid]/stat' file format encountered: " + e.getMessage());
            return null;
        } catch (NumberFormatException e4) {
            e = e4;
            aVar.f("Unexpected '/proc/[pid]/stat' file format encountered: " + e.getMessage());
            return null;
        }
    }
}
