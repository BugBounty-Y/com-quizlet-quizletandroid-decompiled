package com.google.android.gms.common.api.internal;

import android.os.Looper;
import android.util.Log;
import androidx.annotation.NonNull;
import com.google.android.gms.common.annotation.KeepName;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.k;
import com.google.android.gms.internal.ads.AbstractC1794Wd;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3459g3;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@KeepName
/* loaded from: classes2.dex */
public abstract class BasePendingResult<R extends com.google.android.gms.common.api.k> extends AbstractC3459g3 {
    static final ThreadLocal zaa = new androidx.camera.core.impl.utils.executor.b(6);

    @KeepName
    private E resultGuardian;

    @NonNull
    protected final HandlerC1646d zab;

    @NonNull
    protected final WeakReference zac;
    private com.google.android.gms.common.api.k zaj;
    private Status zak;
    private volatile boolean zal;
    private boolean zam;
    private boolean zan;
    private final Object zae = new Object();
    private final CountDownLatch zaf = new CountDownLatch(1);
    private final ArrayList zag = new ArrayList();
    private final AtomicReference zai = new AtomicReference();
    private boolean zaq = false;

    public BasePendingResult(p pVar) {
        this.zab = new HandlerC1646d(pVar != null ? pVar.b.g : Looper.getMainLooper(), 1);
        this.zac = new WeakReference(pVar);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static void zal(com.google.android.gms.common.api.k kVar) {
        if (kVar instanceof AbstractC1794Wd) {
            try {
                ((AbstractC1794Wd) kVar).j();
            } catch (RuntimeException e) {
                Log.w("BasePendingResult", "Unable to release ".concat(String.valueOf(kVar)), e);
            }
        }
    }

    public final void addStatusListener(@NonNull com.google.android.gms.common.api.j jVar) {
        com.google.android.gms.common.internal.u.a("Callback cannot be null.", jVar != null);
        synchronized (this.zae) {
            try {
                if (isReady()) {
                    jVar.a(this.zak);
                } else {
                    this.zag.add(jVar);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @NonNull
    public final R await(long j, @NonNull TimeUnit timeUnit) {
        R r;
        if (j > 0) {
            com.google.android.gms.common.internal.u.g("await must not be called on the UI thread when time is greater than zero.");
        }
        com.google.android.gms.common.internal.u.j("Result has already been consumed.", !this.zal);
        try {
            if (!this.zaf.await(j, timeUnit)) {
                forceFailureUnlessReady(Status.h);
            }
        } catch (InterruptedException unused) {
            forceFailureUnlessReady(Status.f);
        }
        com.google.android.gms.common.internal.u.j("Result is not ready.", isReady());
        synchronized (this.zae) {
            com.google.android.gms.common.internal.u.j("Result has already been consumed.", !this.zal);
            com.google.android.gms.common.internal.u.j("Result is not ready.", isReady());
            r = (R) this.zaj;
            this.zaj = null;
            this.zal = true;
        }
        if (this.zai.getAndSet(null) != null) {
            throw new ClassCastException();
        }
        com.google.android.gms.common.internal.u.h(r);
        return r;
    }

    public abstract com.google.android.gms.common.api.k c(Status status);

    public final void d(com.google.android.gms.common.api.k kVar) {
        this.zaj = kVar;
        this.zak = kVar.getStatus();
        this.zaf.countDown();
        if (!this.zam && (this.zaj instanceof AbstractC1794Wd)) {
            this.resultGuardian = new E(this);
        }
        ArrayList arrayList = this.zag;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            ((com.google.android.gms.common.api.j) arrayList.get(i)).a(this.zak);
        }
        arrayList.clear();
    }

    @Deprecated
    public final void forceFailureUnlessReady(@NonNull Status status) {
        synchronized (this.zae) {
            try {
                if (!isReady()) {
                    setResult(c(status));
                    this.zan = true;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final boolean isReady() {
        return this.zaf.getCount() == 0;
    }

    public final void setResult(@NonNull R r) {
        synchronized (this.zae) {
            try {
                if (this.zan || this.zam) {
                    zal(r);
                    return;
                }
                isReady();
                com.google.android.gms.common.internal.u.j("Results have already been set", !isReady());
                com.google.android.gms.common.internal.u.j("Result has already been consumed", !this.zal);
                d(r);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void zak() {
        boolean z = true;
        if (!this.zaq && !((Boolean) zaa.get()).booleanValue()) {
            z = false;
        }
        this.zaq = z;
    }

    public final /* synthetic */ com.google.android.gms.common.api.k zam() {
        return this.zaj;
    }
}
