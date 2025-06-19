package com.google.android.gms.internal.play_billing;

import java.util.concurrent.CancellationException;

/* loaded from: classes2.dex */
public final class S0 {
    public static final S0 b;
    public static final S0 c;
    public final CancellationException a;

    static {
        if (l2.d) {
            c = null;
            b = null;
        } else {
            c = new S0(null);
            b = new S0(null);
        }
    }

    public S0(CancellationException cancellationException) {
        this.a = cancellationException;
    }
}
