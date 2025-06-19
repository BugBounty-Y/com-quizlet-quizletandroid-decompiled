package androidx.loader.content;

import android.util.Log;
import com.airbnb.lottie.A;
import com.airbnb.lottie.z;
import com.google.android.gms.analytics.g;
import java.lang.Thread;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

/* loaded from: classes.dex */
public final class d extends FutureTask {
    public final /* synthetic */ int a = 0;
    public Object b;

    public /* synthetic */ d(Callable callable) {
        super(callable);
    }

    @Override // java.util.concurrent.FutureTask
    public void done() {
        switch (this.a) {
            case 0:
                a aVar = (a) this.b;
                try {
                    Object obj = get();
                    if (aVar.d.get()) {
                        return;
                    }
                    aVar.a(obj);
                    return;
                } catch (InterruptedException e) {
                    Log.w("AsyncTask", e);
                    return;
                } catch (CancellationException unused) {
                    if (aVar.d.get()) {
                        return;
                    }
                    aVar.a(null);
                    return;
                } catch (ExecutionException e2) {
                    throw new RuntimeException("An error occurred while executing doInBackground()", e2.getCause());
                } catch (Throwable th) {
                    throw new RuntimeException("An error occurred while executing doInBackground()", th);
                }
            case 1:
                try {
                    if (!isCancelled()) {
                        try {
                            ((A) this.b).d((z) get());
                        } catch (InterruptedException | ExecutionException e3) {
                            ((A) this.b).d(new z(e3));
                        }
                    }
                    return;
                } finally {
                    this.b = null;
                }
            default:
                super.done();
                return;
        }
    }

    @Override // java.util.concurrent.FutureTask
    public void setException(Throwable th) {
        switch (this.a) {
            case 2:
                Thread.UncaughtExceptionHandler uncaughtExceptionHandler = ((g) this.b).a.d;
                if (uncaughtExceptionHandler != null) {
                    uncaughtExceptionHandler.uncaughtException(Thread.currentThread(), th);
                } else if (Log.isLoggable("GAv4", 6)) {
                    Log.e("GAv4", "MeasurementExecutor: job failed with ".concat(String.valueOf(th)));
                }
                super.setException(th);
                break;
            default:
                super.setException(th);
                break;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(g gVar, Runnable runnable, Object obj) {
        super(runnable, obj);
        this.b = gVar;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(a aVar, androidx.camera.core.impl.utils.executor.c cVar) {
        super(cVar);
        this.b = aVar;
    }
}
