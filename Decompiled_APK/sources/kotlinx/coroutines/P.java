package kotlinx.coroutines;

import java.util.concurrent.ScheduledFuture;

/* loaded from: classes3.dex */
public final class P implements Q {
    public final ScheduledFuture a;

    public P(ScheduledFuture scheduledFuture) {
        this.a = scheduledFuture;
    }

    @Override // kotlinx.coroutines.Q
    public final void dispose() {
        this.a.cancel(false);
    }

    public final String toString() {
        return "DisposableFutureHandle[" + this.a + ']';
    }
}
