package com.google.android.gms.internal.ads;

import android.content.Context;

/* loaded from: classes2.dex */
public final class Rs extends Qs {
    public static Rs i;

    public static final Rs f(Context context) {
        Rs rs;
        synchronized (Rs.class) {
            try {
                if (i == null) {
                    i = new Rs(context, "paidv1_id", "paidv1_creation_time", "PaidV1LifecycleImpl");
                }
                rs = i;
            } catch (Throwable th) {
                throw th;
            }
        }
        return rs;
    }
}
