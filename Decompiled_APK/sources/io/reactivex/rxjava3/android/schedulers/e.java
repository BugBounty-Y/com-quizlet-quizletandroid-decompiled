package io.reactivex.rxjava3.android.schedulers;

import android.os.Handler;
import android.os.Message;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.tasks.k;
import io.reactivex.rxjava3.core.n;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.schedulers.f;
import io.reactivex.rxjava3.internal.schedulers.h;
import io.reactivex.rxjava3.internal.schedulers.i;
import io.reactivex.rxjava3.internal.schedulers.j;
import io.reactivex.rxjava3.internal.schedulers.r;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public final class e extends o {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ e(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.core.o
    public final n a() {
        switch (this.a) {
            case 0:
                return new c((Handler) this.b);
            default:
                return new i((Executor) this.b);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.reactivex.rxjava3.core.o
    public io.reactivex.rxjava3.disposables.b b(Runnable runnable) {
        h hVar;
        switch (this.a) {
            case 1:
                Executor executor = (Executor) this.b;
                Objects.requireNonNull(runnable, "run is null");
                try {
                    if (executor instanceof ExecutorService) {
                        r rVar = new r(runnable);
                        rVar.a(((ExecutorService) executor).submit(rVar));
                        hVar = rVar;
                    } else {
                        h hVar2 = new h(runnable, null);
                        executor.execute(hVar2);
                        hVar = hVar2;
                    }
                    return hVar;
                } catch (RejectedExecutionException e) {
                    C7.c(e);
                    return io.reactivex.rxjava3.internal.disposables.b.a;
                }
            default:
                return super.b(runnable);
        }
    }

    @Override // io.reactivex.rxjava3.core.o
    public final io.reactivex.rxjava3.disposables.b c(Runnable runnable, long j, TimeUnit timeUnit) {
        switch (this.a) {
            case 0:
                if (runnable == null) {
                    throw new NullPointerException("run == null");
                }
                if (timeUnit == null) {
                    throw new NullPointerException("unit == null");
                }
                Handler handler = (Handler) this.b;
                d dVar = new d(handler, runnable);
                Message messageObtain = Message.obtain(handler, dVar);
                messageObtain.setAsynchronous(true);
                handler.sendMessageDelayed(messageObtain, timeUnit.toMillis(j));
                return dVar;
            default:
                Objects.requireNonNull(runnable, "run is null");
                Executor executor = (Executor) this.b;
                if (executor instanceof ScheduledExecutorService) {
                    try {
                        r rVar = new r(runnable);
                        rVar.a(((ScheduledExecutorService) executor).schedule(rVar, j, timeUnit));
                        return rVar;
                    } catch (RejectedExecutionException e) {
                        C7.c(e);
                        return io.reactivex.rxjava3.internal.disposables.b.a;
                    }
                }
                f fVar = new f(runnable);
                io.reactivex.rxjava3.disposables.b bVarC = j.a.c(new k(7, this, fVar), j, timeUnit);
                io.reactivex.rxjava3.disposables.d dVar2 = fVar.a;
                dVar2.getClass();
                io.reactivex.rxjava3.internal.disposables.a.c(dVar2, bVarC);
                return fVar;
        }
    }
}
