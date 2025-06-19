package androidx.work;

import android.content.Context;
import android.net.Network;
import android.net.Uri;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes.dex */
public abstract class y {
    public final Context a;
    public final WorkerParameters b;
    public final AtomicInteger c = new AtomicInteger(-256);
    public boolean d;

    public y(Context context, WorkerParameters workerParameters) {
        if (context == null) {
            throw new IllegalArgumentException("Application Context is null");
        }
        if (workerParameters == null) {
            throw new IllegalArgumentException("WorkerParameters is null");
        }
        this.a = context;
        this.b = workerParameters;
    }

    @NonNull
    public final Context getApplicationContext() {
        return this.a;
    }

    @NonNull
    public Executor getBackgroundExecutor() {
        return this.b.f;
    }

    public abstract com.google.common.util.concurrent.e getForegroundInfoAsync();

    @NonNull
    public final UUID getId() {
        return this.b.a;
    }

    @NonNull
    public final C1437k getInputData() {
        return this.b.b;
    }

    public final Network getNetwork() {
        return (Network) this.b.d.d;
    }

    public final int getRunAttemptCount() {
        return this.b.e;
    }

    public final int getStopReason() {
        return this.c.get();
    }

    @NonNull
    public final Set<String> getTags() {
        return this.b.c;
    }

    @NonNull
    public androidx.work.impl.utils.taskexecutor.a getTaskExecutor() {
        return this.b.h;
    }

    @NonNull
    public final List<String> getTriggeredContentAuthorities() {
        return (List) this.b.d.b;
    }

    @NonNull
    public final List<Uri> getTriggeredContentUris() {
        return (List) this.b.d.c;
    }

    @NonNull
    public T getWorkerFactory() {
        return this.b.i;
    }

    public final boolean isStopped() {
        return this.c.get() != -256;
    }

    public final boolean isUsed() {
        return this.d;
    }

    public void onStopped() {
    }

    @NonNull
    public final com.google.common.util.concurrent.e setForegroundAsync(@NonNull C1442p c1442p) {
        androidx.work.impl.utils.p pVar = this.b.k;
        Context applicationContext = getApplicationContext();
        UUID id = getId();
        androidx.work.impl.utils.taskexecutor.c cVar = pVar.a;
        return AbstractC3394t2.h(cVar.a, "setForegroundAsync", new androidx.work.impl.utils.o(pVar, id, c1442p, applicationContext, 0));
    }

    @NonNull
    public com.google.common.util.concurrent.e setProgressAsync(@NonNull C1437k c1437k) {
        androidx.work.impl.utils.r rVar = this.b.j;
        getApplicationContext();
        UUID id = getId();
        androidx.work.impl.utils.taskexecutor.c cVar = rVar.b;
        return AbstractC3394t2.h(cVar.a, "updateProgress", new androidx.work.impl.utils.q(rVar, id, c1437k, 0));
    }

    public final void setUsed() {
        this.d = true;
    }

    public abstract com.google.common.util.concurrent.e startWork();

    public final void stop(int i) {
        if (this.c.compareAndSet(-256, i)) {
            onStopped();
        }
    }
}
