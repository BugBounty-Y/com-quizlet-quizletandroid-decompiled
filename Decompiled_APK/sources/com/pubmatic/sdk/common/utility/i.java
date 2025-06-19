package com.pubmatic.sdk.common.utility;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import java.util.Locale;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public class i {
    private static final ScheduledThreadPoolExecutor a = new ScheduledThreadPoolExecutor(1);
    private boolean b;
    private com.pubmatic.sdk.common.network.j c;
    private com.pubmatic.sdk.common.network.i d;
    private ScheduledFuture<?> e = null;
    private h f;
    private boolean g;
    private boolean h;
    private long i;

    public class a implements com.pubmatic.sdk.common.network.j {
        public a() {
        }

        @Override // com.pubmatic.sdk.common.network.j
        public void onNetworkConnectionChanged(boolean z) {
            i.this.b = z;
            POBLog.debug("POBLooper", "Network connectivity = " + i.this.b, new Object[0]);
            i iVar = i.this;
            iVar.a(iVar.b);
        }
    }

    public class b implements Runnable {
        public b() {
        }

        @Override // java.lang.Runnable
        public void run() {
            o.runOnMainThread(new p(this));
        }
    }

    private void c() {
        ScheduledFuture<?> scheduledFuture = this.e;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(true);
            this.e = null;
        }
    }

    private void d() {
        com.pubmatic.sdk.common.network.i iVar;
        com.pubmatic.sdk.common.network.j jVar = this.c;
        if (jVar == null || (iVar = this.d) == null) {
            return;
        }
        iVar.unregisterConnectivityListener(jVar);
        this.c = null;
    }

    public synchronized void destroy() {
        d();
        c();
        this.g = false;
        this.h = false;
    }

    public synchronized void forcePause() {
        try {
            if (this.h) {
                POBLog.verbose("POBLooper", "Skipping pause as already in force-paused state.", new Object[0]);
            } else {
                POBLog.verbose("POBLooper", "Applying force-paused state.", new Object[0]);
                this.h = true;
                d();
                pause();
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public synchronized void forceResume() {
        try {
            if (this.h) {
                POBLog.verbose("POBLooper", "Removing force-paused state.", new Object[0]);
                this.h = false;
                b();
                resume();
            } else {
                POBLog.verbose("POBLooper", "Skipping resume as not in force-paused state.", new Object[0]);
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public synchronized void loop(long j) {
        try {
            this.g = true;
            this.i = j * 1000;
            c();
            if (this.h) {
                POBLog.verbose("POBLooper", "Deferring refresh, expecting resumeAutoRefresh to continue the refresh", new Object[0]);
            } else {
                POBLog.verbose("POBLooper", "Refreshing after %s seconds", a(this.i));
                a(this.i);
                b();
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public synchronized void pause() {
        try {
            if (this.g) {
                ScheduledFuture<?> scheduledFuture = this.e;
                if (scheduledFuture != null) {
                    this.i = scheduledFuture.getDelay(TimeUnit.MILLISECONDS);
                    this.e.cancel(true);
                    this.e = null;
                    POBLog.verbose("POBLooper", "Pausing refresh at %s seconds", a(this.i));
                }
            } else {
                POBLog.verbose("POBLooper", "Deferring pausing as not yet looped.", new Object[0]);
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public synchronized void resume() {
        if (this.h) {
            POBLog.verbose("POBLooper", "Skipping resume as in force-paused state.", new Object[0]);
            return;
        }
        if (this.g && this.b) {
            POBLog.verbose("POBLooper", "Resuming refresh from %s seconds", a(this.i));
            a(this.i);
        }
    }

    public void setListener(h hVar) {
        this.f = hVar;
    }

    public void setNetworkMonitor(@NonNull com.pubmatic.sdk.common.network.i iVar) {
        this.d = iVar;
        this.b = iVar.isNetworkAvailable();
    }

    private synchronized void a(long j) {
        if (this.e == null) {
            this.e = a.schedule(new b(), j, TimeUnit.MILLISECONDS);
        }
    }

    private void b() {
        if (this.c != null || this.d == null) {
            return;
        }
        this.c = new a();
        this.b = this.d.isNetworkAvailable();
        this.d.registerConnectivityListener(this.c);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a() {
        if (this.f != null) {
            this.g = false;
            POBLog.verbose("POBLooper", "Invoking scheduled method", new Object[0]);
            this.f.invoke();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(boolean z) {
        if (z) {
            resume();
        } else {
            pause();
        }
    }

    private String a(double d) {
        return String.format(Locale.getDefault(), "%.2f", Double.valueOf(d / 1000.0d));
    }
}
