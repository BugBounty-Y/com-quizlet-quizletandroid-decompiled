package kotlinx.io;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

/* loaded from: classes3.dex */
public final class f extends j {
    public static final AtomicIntegerFieldUpdater b = AtomicIntegerFieldUpdater.newUpdater(f.class, "copyCount");
    private volatile int copyCount;

    @Override // kotlinx.io.j
    public final boolean b() {
        return this.copyCount > 0;
    }

    @Override // kotlinx.io.j
    public final boolean g() {
        if (this.copyCount == 0) {
            return false;
        }
        int iDecrementAndGet = b.decrementAndGet(this);
        if (iDecrementAndGet >= 0) {
            return true;
        }
        if (iDecrementAndGet == -1) {
            this.copyCount = 0;
            return false;
        }
        throw new IllegalStateException(("Shared copies count is negative: " + (iDecrementAndGet + 1)).toString());
    }
}
