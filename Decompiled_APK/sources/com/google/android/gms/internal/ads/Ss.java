package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;

/* loaded from: classes2.dex */
public final class Ss extends Qs {
    public static Ss i;

    public static final Ss g(Context context) {
        Ss ss;
        synchronized (Ss.class) {
            try {
                if (i == null) {
                    i = new Ss(context, "paidv2_id", "paidv2_creation_time", "PaidV2LifecycleImpl");
                }
                ss = i;
            } catch (Throwable th) {
                throw th;
            }
        }
        return ss;
    }

    public final Ns f(long j, boolean z) {
        boolean z2;
        synchronized (Ss.class) {
            try {
                Os os = this.g;
                os.getClass();
                synchronized (Os.class) {
                    z2 = ((SharedPreferences) ((Ps) os.b).b).getBoolean("paidv2_publisher_option", true);
                }
                if (z2) {
                    return a(j, null, null, z);
                }
                return new Ns();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void h() {
        synchronized (Ss.class) {
            try {
                if (((SharedPreferences) this.f.b).contains(this.a)) {
                    d(false);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
