package androidx.camera.core.impl.utils.futures;

import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public class d implements com.google.common.util.concurrent.e {
    public final com.google.common.util.concurrent.e a;
    public androidx.concurrent.futures.i b;

    public d(com.google.common.util.concurrent.e eVar) {
        eVar.getClass();
        this.a = eVar;
    }

    public static d c(com.google.common.util.concurrent.e eVar) {
        return eVar instanceof d ? (d) eVar : new d(eVar);
    }

    @Override // com.google.common.util.concurrent.e
    public final void a(Runnable runnable, Executor executor) {
        this.a.a(runnable, executor);
    }

    @Override // java.util.concurrent.Future
    public boolean cancel(boolean z) {
        return this.a.cancel(z);
    }

    @Override // java.util.concurrent.Future
    public Object get() {
        return this.a.get();
    }

    @Override // java.util.concurrent.Future
    public final boolean isCancelled() {
        return this.a.isCancelled();
    }

    @Override // java.util.concurrent.Future
    public final boolean isDone() {
        return this.a.isDone();
    }

    @Override // java.util.concurrent.Future
    public Object get(long j, TimeUnit timeUnit) {
        return this.a.get(j, timeUnit);
    }

    public d() {
        this.a = Y5.b(new com.airbnb.lottie.network.d(this, 7));
    }
}
