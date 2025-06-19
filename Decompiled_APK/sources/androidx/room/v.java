package androidx.room;

import androidx.work.impl.WorkDatabase_Impl;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class v implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ w b;

    public /* synthetic */ v(w wVar, int i) {
        this.a = i;
        this.b = wVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        AtomicBoolean atomicBoolean;
        boolean z;
        Executor executor;
        switch (this.a) {
            case 0:
                w this$0 = this.b;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                if (this$0.s.compareAndSet(false, true)) {
                    n nVar = this$0.l.e;
                    nVar.getClass();
                    c observer = this$0.p;
                    Intrinsics.checkNotNullParameter(observer, "observer");
                    nVar.a(new m(nVar, observer));
                }
                do {
                    AtomicBoolean atomicBoolean2 = this$0.r;
                    boolean zCompareAndSet = atomicBoolean2.compareAndSet(false, true);
                    atomicBoolean = this$0.q;
                    if (zCompareAndSet) {
                        Object objCall = null;
                        z = false;
                        while (atomicBoolean.compareAndSet(true, false)) {
                            try {
                                try {
                                    objCall = this$0.o.call();
                                    z = true;
                                } catch (Exception e) {
                                    throw new RuntimeException("Exception while computing database live data.", e);
                                }
                            } finally {
                                atomicBoolean2.set(false);
                            }
                        }
                        if (z) {
                            this$0.j(objCall);
                        }
                    } else {
                        z = false;
                    }
                    if (!z) {
                        return;
                    }
                } while (atomicBoolean.get());
                return;
            default:
                w this$02 = this.b;
                Intrinsics.checkNotNullParameter(this$02, "this$0");
                boolean zE = this$02.e();
                if (this$02.q.compareAndSet(false, true) && zE) {
                    boolean z2 = this$02.n;
                    WorkDatabase_Impl workDatabase_Impl = this$02.l;
                    if (z2) {
                        executor = workDatabase_Impl.c;
                        if (executor == null) {
                            Intrinsics.m("internalTransactionExecutor");
                            throw null;
                        }
                    } else {
                        executor = workDatabase_Impl.b;
                        if (executor == null) {
                            Intrinsics.m("internalQueryExecutor");
                            throw null;
                        }
                    }
                    executor.execute(this$02.t);
                    return;
                }
                return;
        }
    }
}
