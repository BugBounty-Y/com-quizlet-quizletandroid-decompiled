package io.reactivex.rxjava3.internal.operators.flowable;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.google.android.gms.internal.mlkit_vision_barcode.z7;
import com.quizlet.remote.model.school.h;
import io.reactivex.rxjava3.exceptions.CompositeException;
import io.reactivex.rxjava3.exceptions.ProtocolViolationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class e extends AtomicInteger implements io.reactivex.rxjava3.core.f, org.reactivestreams.b {
    public org.reactivestreams.b a;
    public long b;
    public final AtomicReference c = new AtomicReference();
    public final AtomicLong d = new AtomicLong();
    public final AtomicLong e = new AtomicLong();
    public volatile boolean f;
    public boolean g;
    public final io.reactivex.rxjava3.core.f h;
    public final h i;
    public boolean j;
    public boolean k;
    public long l;

    public e(io.reactivex.rxjava3.core.f fVar, h hVar) {
        this.h = fVar;
        this.i = hVar;
    }

    public final void a() {
        if (getAndIncrement() != 0) {
            return;
        }
        d();
    }

    @Override // io.reactivex.rxjava3.core.f
    public final void b(Object obj) {
        if (this.k) {
            return;
        }
        if (!this.j) {
            this.l++;
        }
        this.h.b(obj);
    }

    @Override // io.reactivex.rxjava3.core.f
    public final void c(org.reactivestreams.b bVar) {
        if (this.f) {
            bVar.cancel();
            return;
        }
        if (get() != 0 || !compareAndSet(0, 1)) {
            a();
            return;
        }
        this.a = bVar;
        long j = this.b;
        if (decrementAndGet() != 0) {
            d();
        }
        if (j != 0) {
            bVar.e(j);
        }
    }

    @Override // org.reactivestreams.b
    public final void cancel() {
        if (this.f) {
            return;
        }
        this.f = true;
        a();
    }

    public final void d() {
        int iAddAndGet = 1;
        long jG = 0;
        org.reactivestreams.b bVar = null;
        do {
            org.reactivestreams.b bVar2 = (org.reactivestreams.b) this.c.get();
            if (bVar2 != null) {
                bVar2 = (org.reactivestreams.b) this.c.getAndSet(null);
            }
            long andSet = this.d.get();
            if (andSet != 0) {
                andSet = this.d.getAndSet(0L);
            }
            long andSet2 = this.e.get();
            if (andSet2 != 0) {
                andSet2 = this.e.getAndSet(0L);
            }
            org.reactivestreams.b bVar3 = this.a;
            if (this.f) {
                if (bVar3 != null) {
                    bVar3.cancel();
                    this.a = null;
                }
                if (bVar2 != null) {
                    bVar2.cancel();
                }
            } else {
                long jG2 = this.b;
                if (jG2 != Long.MAX_VALUE) {
                    jG2 = z7.g(jG2, andSet);
                    if (jG2 != Long.MAX_VALUE) {
                        jG2 -= andSet2;
                        if (jG2 < 0) {
                            C7.c(new ProtocolViolationException(d0.n(jG2, "More produced than requested: ")));
                            jG2 = 0;
                        }
                    }
                    this.b = jG2;
                }
                if (bVar2 != null) {
                    this.a = bVar2;
                    if (jG2 != 0) {
                        jG = z7.g(jG, jG2);
                        bVar = bVar2;
                    }
                } else if (bVar3 != null && andSet != 0) {
                    jG = z7.g(jG, andSet);
                    bVar = bVar3;
                }
            }
            iAddAndGet = addAndGet(-iAddAndGet);
        } while (iAddAndGet != 0);
        if (jG != 0) {
            bVar.e(jG);
        }
    }

    @Override // org.reactivestreams.b
    public final void e(long j) {
        if (!io.reactivex.rxjava3.internal.subscriptions.c.c(j) || this.g) {
            return;
        }
        if (get() != 0 || !compareAndSet(0, 1)) {
            z7.f(this.d, j);
            a();
            return;
        }
        long j2 = this.b;
        if (j2 != Long.MAX_VALUE) {
            long jG = z7.g(j2, j);
            this.b = jG;
            if (jG == Long.MAX_VALUE) {
                this.g = true;
            }
        }
        org.reactivestreams.b bVar = this.a;
        if (decrementAndGet() != 0) {
            d();
        }
        if (bVar != null) {
            bVar.e(j);
        }
    }

    @Override // io.reactivex.rxjava3.core.f
    public final void onComplete() {
        if (this.k) {
            return;
        }
        this.k = true;
        this.j = true;
        this.h.onComplete();
    }

    @Override // io.reactivex.rxjava3.core.f
    public final void onError(Throwable th) {
        boolean z = this.j;
        io.reactivex.rxjava3.core.f fVar = this.h;
        if (z) {
            if (this.k) {
                C7.c(th);
                return;
            } else {
                fVar.onError(th);
                return;
            }
        }
        this.j = true;
        try {
            org.reactivestreams.a aVar = (org.reactivestreams.a) this.i.apply(th);
            long j = this.l;
            long j2 = 0;
            if (j != 0 && !this.g) {
                if (get() == 0 && compareAndSet(0, 1)) {
                    long j3 = this.b;
                    if (j3 != Long.MAX_VALUE) {
                        long j4 = j3 - j;
                        if (j4 < 0) {
                            C7.c(new ProtocolViolationException(d0.n(j4, "More produced than requested: ")));
                        } else {
                            j2 = j4;
                        }
                        this.b = j2;
                    }
                    if (decrementAndGet() != 0) {
                        d();
                    }
                } else {
                    z7.f(this.e, j);
                    a();
                }
            }
            ((io.reactivex.rxjava3.core.e) aVar).a(this);
        } catch (Throwable th2) {
            x7.b(th2);
            fVar.onError(new CompositeException(th, th2));
        }
    }
}
