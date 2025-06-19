package com.google.android.gms.internal.play_billing;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class E0 extends AbstractC3830r0 {
    public InterfaceFutureC3845w0 h;
    public ScheduledFuture i;

    @Override // com.google.android.gms.internal.play_billing.AbstractC3816m0
    public final String c() {
        InterfaceFutureC3845w0 interfaceFutureC3845w0 = this.h;
        ScheduledFuture scheduledFuture = this.i;
        if (interfaceFutureC3845w0 == null) {
            return null;
        }
        String strB = android.support.v4.media.session.a.B("inputFuture=[", interfaceFutureC3845w0.toString(), "]");
        if (scheduledFuture == null) {
            return strB;
        }
        long delay = scheduledFuture.getDelay(TimeUnit.MILLISECONDS);
        if (delay <= 0) {
            return strB;
        }
        return strB + ", remaining delay=[" + delay + " ms]";
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3816m0
    public final void d() {
        InterfaceFutureC3845w0 interfaceFutureC3845w0 = this.h;
        if ((interfaceFutureC3845w0 != null) & (this.a instanceof C3786c0)) {
            Object obj = this.a;
            interfaceFutureC3845w0.cancel((obj instanceof C3786c0) && ((C3786c0) obj).a);
        }
        ScheduledFuture scheduledFuture = this.i;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(false);
        }
        this.h = null;
        this.i = null;
    }
}
