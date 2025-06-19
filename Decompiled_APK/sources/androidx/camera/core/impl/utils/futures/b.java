package androidx.camera.core.impl.utils.futures;

import com.google.android.gms.internal.mlkit_vision_barcode.T;
import java.lang.reflect.UndeclaredThrowableException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/* loaded from: classes.dex */
public final class b extends d implements Runnable {
    public a c;
    public final LinkedBlockingQueue d = new LinkedBlockingQueue(1);
    public final CountDownLatch e = new CountDownLatch(1);
    public com.google.common.util.concurrent.e f;
    public volatile com.google.common.util.concurrent.e g;

    public b(a aVar, com.google.common.util.concurrent.e eVar) {
        this.c = aVar;
        eVar.getClass();
        this.f = eVar;
    }

    public static Object d(LinkedBlockingQueue linkedBlockingQueue) {
        Object objTake;
        boolean z = false;
        while (true) {
            try {
                objTake = linkedBlockingQueue.take();
                break;
            } catch (InterruptedException unused) {
                z = true;
            } catch (Throwable th) {
                if (z) {
                    Thread.currentThread().interrupt();
                }
                throw th;
            }
        }
        if (z) {
            Thread.currentThread().interrupt();
        }
        return objTake;
    }

    @Override // androidx.camera.core.impl.utils.futures.d, java.util.concurrent.Future
    public final boolean cancel(boolean z) {
        boolean z2 = false;
        if (!this.a.cancel(z)) {
            return false;
        }
        while (true) {
            try {
                this.d.put(Boolean.valueOf(z));
                break;
            } catch (InterruptedException unused) {
                z2 = true;
            } catch (Throwable th) {
                if (z2) {
                    Thread.currentThread().interrupt();
                }
                throw th;
            }
        }
        if (z2) {
            Thread.currentThread().interrupt();
        }
        com.google.common.util.concurrent.e eVar = this.f;
        if (eVar != null) {
            eVar.cancel(z);
        }
        com.google.common.util.concurrent.e eVar2 = this.g;
        if (eVar2 != null) {
            eVar2.cancel(z);
        }
        return true;
    }

    @Override // androidx.camera.core.impl.utils.futures.d, java.util.concurrent.Future
    public final Object get() throws ExecutionException, InterruptedException {
        if (!this.a.isDone()) {
            com.google.common.util.concurrent.e eVar = this.f;
            if (eVar != null) {
                eVar.get();
            }
            this.e.await();
            com.google.common.util.concurrent.e eVar2 = this.g;
            if (eVar2 != null) {
                eVar2.get();
            }
        }
        return this.a.get();
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [androidx.camera.core.impl.utils.futures.a, com.google.common.util.concurrent.e] */
    /* JADX WARN: Type inference failed for: r0v1, types: [androidx.camera.core.impl.utils.futures.a, com.google.common.util.concurrent.e] */
    /* JADX WARN: Type inference failed for: r0v10 */
    /* JADX WARN: Type inference failed for: r0v11 */
    /* JADX WARN: Type inference failed for: r0v12 */
    /* JADX WARN: Type inference failed for: r0v13 */
    /* JADX WARN: Type inference failed for: r0v14 */
    /* JADX WARN: Type inference failed for: r0v15 */
    /* JADX WARN: Type inference failed for: r0v16 */
    /* JADX WARN: Type inference failed for: r0v17 */
    /* JADX WARN: Type inference failed for: r0v18 */
    /* JADX WARN: Type inference failed for: r0v3 */
    /* JADX WARN: Type inference failed for: r0v4, types: [androidx.camera.core.impl.utils.futures.a, com.google.common.util.concurrent.e] */
    /* JADX WARN: Type inference failed for: r0v6 */
    /* JADX WARN: Type inference failed for: r0v7 */
    /* JADX WARN: Type inference failed for: r0v8, types: [java.util.concurrent.CountDownLatch] */
    /* JADX WARN: Type inference failed for: r0v9 */
    @Override // java.lang.Runnable
    public final void run() {
        ?? r0;
        ?? r02 = 0;
        r02 = 0;
        r02 = 0;
        r02 = 0;
        r02 = 0;
        try {
            try {
                try {
                    try {
                        try {
                            com.google.common.util.concurrent.e eVarApply = this.c.apply(i.b(this.f));
                            this.g = eVarApply;
                            if (this.a.isCancelled()) {
                                eVarApply.cancel(((Boolean) d(this.d)).booleanValue());
                                this.g = null;
                            } else {
                                eVarApply.a(new com.google.common.util.concurrent.d(this, false, eVarApply, 1), T.a());
                            }
                        } catch (Exception e) {
                            androidx.concurrent.futures.i iVar = this.b;
                            r0 = r02;
                            if (iVar != null) {
                                iVar.d(e);
                                r0 = r02;
                            }
                        }
                    } catch (Error e2) {
                        androidx.concurrent.futures.i iVar2 = this.b;
                        r0 = r02;
                        if (iVar2 != null) {
                            iVar2.d(e2);
                            r0 = r02;
                        }
                    }
                } finally {
                    this.c = r02;
                    this.f = r02;
                    this.e.countDown();
                }
            } catch (CancellationException unused) {
                cancel(false);
            } catch (ExecutionException e3) {
                Throwable cause = e3.getCause();
                androidx.concurrent.futures.i iVar3 = this.b;
                if (iVar3 != null) {
                    iVar3.d(cause);
                }
            }
        } catch (UndeclaredThrowableException e4) {
            Throwable cause2 = e4.getCause();
            androidx.concurrent.futures.i iVar4 = this.b;
            r0 = r02;
            if (iVar4 != null) {
                iVar4.d(cause2);
                r0 = r02;
            }
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.d, java.util.concurrent.Future
    public final Object get(long j, TimeUnit timeUnit) throws ExecutionException, InterruptedException, TimeoutException {
        if (!this.a.isDone()) {
            TimeUnit timeUnit2 = TimeUnit.NANOSECONDS;
            if (timeUnit != timeUnit2) {
                j = timeUnit2.convert(j, timeUnit);
                timeUnit = timeUnit2;
            }
            com.google.common.util.concurrent.e eVar = this.f;
            if (eVar != null) {
                long jNanoTime = System.nanoTime();
                eVar.get(j, timeUnit);
                j -= Math.max(0L, System.nanoTime() - jNanoTime);
            }
            long jNanoTime2 = System.nanoTime();
            if (this.e.await(j, timeUnit)) {
                j -= Math.max(0L, System.nanoTime() - jNanoTime2);
                com.google.common.util.concurrent.e eVar2 = this.g;
                if (eVar2 != null) {
                    eVar2.get(j, timeUnit);
                }
            } else {
                throw new TimeoutException();
            }
        }
        return this.a.get(j, timeUnit);
    }
}
