package com.google.android.gms.internal.measurement;

import android.os.SystemClock;

/* renamed from: com.google.android.gms.internal.measurement.f0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractRunnableC2988f0 implements Runnable {
    public final long a;
    public final long b;
    public final boolean c;
    public final /* synthetic */ C3008j0 d;

    public AbstractRunnableC2988f0(C3008j0 c3008j0, boolean z) {
        this.d = c3008j0;
        c3008j0.b.getClass();
        this.a = System.currentTimeMillis();
        c3008j0.b.getClass();
        this.b = SystemClock.elapsedRealtime();
        this.c = z;
    }

    public abstract void a();

    public void b() {
    }

    @Override // java.lang.Runnable
    public final void run() {
        C3008j0 c3008j0 = this.d;
        if (c3008j0.g) {
            b();
            return;
        }
        try {
            a();
        } catch (Exception e) {
            c3008j0.b(e, false, this.c);
            b();
        }
    }
}
