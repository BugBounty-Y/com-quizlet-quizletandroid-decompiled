package com.google.android.gms.internal.ads;

import android.os.SystemClock;

/* renamed from: com.google.android.gms.internal.ads.dj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1973dj {
    public boolean a;

    public final synchronized void a() {
        boolean z = false;
        while (!this.a) {
            try {
                wait();
            } catch (InterruptedException unused) {
                z = true;
            }
        }
        if (z) {
            Thread.currentThread().interrupt();
        }
    }

    public final synchronized boolean b(long j) {
        if (j > 0) {
            try {
                long jElapsedRealtime = SystemClock.elapsedRealtime();
                long j2 = j + jElapsedRealtime;
                if (j2 < jElapsedRealtime) {
                    a();
                } else {
                    boolean z = false;
                    while (!this.a && jElapsedRealtime < j2) {
                        try {
                            wait(j2 - jElapsedRealtime);
                        } catch (InterruptedException unused) {
                            z = true;
                        }
                        jElapsedRealtime = SystemClock.elapsedRealtime();
                    }
                    if (z) {
                        Thread.currentThread().interrupt();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return this.a;
    }

    public final synchronized boolean c() {
        if (this.a) {
            return false;
        }
        this.a = true;
        notifyAll();
        return true;
    }
}
