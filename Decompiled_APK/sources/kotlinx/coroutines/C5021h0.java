package kotlinx.coroutines;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.jvm.functions.Function1;

/* renamed from: kotlinx.coroutines.h0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5021h0 extends l0 {
    public static final /* synthetic */ AtomicIntegerFieldUpdater f = AtomicIntegerFieldUpdater.newUpdater(C5021h0.class, "_invoked$volatile");
    private volatile /* synthetic */ int _invoked$volatile;
    public final Function1 e;

    public C5021h0(Function1 function1) {
        this.e = function1;
    }

    @Override // kotlinx.coroutines.l0
    public final boolean j() {
        return true;
    }

    @Override // kotlinx.coroutines.l0
    public final void k(Throwable th) {
        if (f.compareAndSet(this, 0, 1)) {
            this.e.invoke(th);
        }
    }
}
