package com.google.android.gms.internal.ads;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.fw, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2073fw extends Mv {
    public com.google.common.util.concurrent.e h;
    public ScheduledFuture i;

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final String e() {
        com.google.common.util.concurrent.e eVar = this.h;
        ScheduledFuture scheduledFuture = this.i;
        if (eVar == null) {
            return null;
        }
        String strB = android.support.v4.media.session.a.B("inputFuture=[", eVar.toString(), "]");
        if (scheduledFuture == null) {
            return strB;
        }
        long delay = scheduledFuture.getDelay(TimeUnit.MILLISECONDS);
        if (delay <= 0) {
            return strB;
        }
        return strB + ", remaining delay=[" + delay + " ms]";
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final void f() {
        m(this.h);
        ScheduledFuture scheduledFuture = this.i;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(false);
        }
        this.h = null;
        this.i = null;
    }
}
