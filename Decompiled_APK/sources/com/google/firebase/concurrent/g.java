package com.google.firebase.concurrent;

import java.util.concurrent.Delayed;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class g extends androidx.concurrent.futures.h implements ScheduledFuture {
    public final ScheduledFuture h;

    public g(f fVar) {
        this.h = fVar.b(new com.quizlet.data.repository.school.membership.a(this, 24));
    }

    @Override // java.lang.Comparable
    public final int compareTo(Delayed delayed) {
        return this.h.compareTo(delayed);
    }

    @Override // androidx.concurrent.futures.h
    public final void d() {
        ScheduledFuture scheduledFuture = this.h;
        Object obj = this.a;
        scheduledFuture.cancel((obj instanceof androidx.concurrent.futures.a) && ((androidx.concurrent.futures.a) obj).a);
    }

    @Override // java.util.concurrent.Delayed
    public final long getDelay(TimeUnit timeUnit) {
        return this.h.getDelay(timeUnit);
    }
}
