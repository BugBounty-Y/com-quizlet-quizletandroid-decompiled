package com.google.firebase.analytics;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.measurement.C2983e0;
import com.google.android.gms.internal.measurement.C3008j0;
import com.google.android.gms.internal.measurement.U;
import com.google.android.gms.internal.measurement.zzdj;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.measurement.internal.E0;
import com.google.firebase.h;
import com.google.firebase.installations.c;
import com.google.firebase.installations.d;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/* loaded from: classes2.dex */
public final class FirebaseAnalytics {
    public static volatile FirebaseAnalytics b;
    public final C3008j0 a;

    public FirebaseAnalytics(C3008j0 c3008j0) {
        u.h(c3008j0);
        this.a = c3008j0;
    }

    @NonNull
    @Keep
    public static FirebaseAnalytics getInstance(@NonNull Context context) {
        if (b == null) {
            synchronized (FirebaseAnalytics.class) {
                try {
                    if (b == null) {
                        b = new FirebaseAnalytics(C3008j0.f(context, null, null, null, null));
                    }
                } finally {
                }
            }
        }
        return b;
    }

    @Keep
    public static E0 getScionFrontendApiImplementation(Context context, Bundle bundle) {
        C3008j0 c3008j0F = C3008j0.f(context, null, null, null, bundle);
        if (c3008j0F == null) {
            return null;
        }
        return new a(c3008j0F);
    }

    public final void a(Bundle bundle, String str) {
        C3008j0 c3008j0 = this.a;
        c3008j0.getClass();
        c3008j0.c(new C2983e0(c3008j0, null, null, str, bundle, false, true));
    }

    @NonNull
    @Keep
    public String getFirebaseInstanceId() {
        try {
            Object obj = c.m;
            return (String) S3.f(((c) h.c().b(d.class)).c(), 30000L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        } catch (ExecutionException e2) {
            throw new IllegalStateException(e2.getCause());
        } catch (TimeoutException unused) {
            throw new IllegalThreadStateException("Firebase Installations getId Task has timed out.");
        }
    }

    @Keep
    @Deprecated
    public void setCurrentScreen(@NonNull Activity activity, String str, String str2) {
        zzdj zzdjVarA = zzdj.a(activity);
        C3008j0 c3008j0 = this.a;
        c3008j0.getClass();
        c3008j0.c(new U(c3008j0, zzdjVarA, str, str2));
    }
}
