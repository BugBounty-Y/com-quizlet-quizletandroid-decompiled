package androidx.privacysandbox.ads.adservices.java.measurement;

import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.view.InputEvent;
import com.google.android.gms.internal.mlkit_vision_camera.T1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class h {
    public final androidx.privacysandbox.ads.adservices.measurement.e a;

    public h(androidx.privacysandbox.ads.adservices.measurement.e mMeasurementManager) {
        Intrinsics.checkNotNullParameter(mMeasurementManager, "mMeasurementManager");
        this.a = mMeasurementManager;
    }

    public static final h b(Context context) {
        androidx.privacysandbox.ads.adservices.measurement.e cVar;
        Object objInvoke;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        int i = Build.VERSION.SDK_INT;
        androidx.privacysandbox.ads.adservices.internal.b bVar = androidx.privacysandbox.ads.adservices.internal.b.a;
        if (i >= 33) {
            bVar.a();
        }
        if ((i >= 33 ? bVar.a() : 0) >= 5) {
            cVar = new androidx.privacysandbox.ads.adservices.measurement.c(context);
        } else {
            androidx.privacysandbox.ads.adservices.internal.a aVar = androidx.privacysandbox.ads.adservices.internal.a.a;
            if (((i == 31 || i == 32) ? aVar.a() : 0) >= 9) {
                androidx.camera.lifecycle.d manager = new androidx.camera.lifecycle.d(context, 1);
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter("MeasurementManager", "tag");
                Intrinsics.checkNotNullParameter(manager, "manager");
                try {
                    objInvoke = manager.invoke(context);
                } catch (NoClassDefFoundError unused) {
                    int i2 = Build.VERSION.SDK_INT;
                    if (i2 == 31 || i2 == 32) {
                        aVar.a();
                    }
                    objInvoke = null;
                }
                cVar = (androidx.privacysandbox.ads.adservices.measurement.e) objInvoke;
            } else {
                cVar = null;
            }
        }
        if (cVar != null) {
            return new h(cVar);
        }
        return null;
    }

    @NotNull
    public com.google.common.util.concurrent.e a(@NotNull androidx.privacysandbox.ads.adservices.measurement.a deletionRequest) {
        Intrinsics.checkNotNullParameter(deletionRequest, "deletionRequest");
        return T1.e(E.f(E.c(O.a), null, new a(this, null), 3));
    }

    @NotNull
    public com.google.common.util.concurrent.e c() {
        return T1.e(E.f(E.c(O.a), null, new b(this, null), 3));
    }

    @NotNull
    public com.google.common.util.concurrent.e d(@NotNull Uri attributionSource, InputEvent inputEvent) {
        Intrinsics.checkNotNullParameter(attributionSource, "attributionSource");
        return T1.e(E.f(E.c(O.a), null, new c(this, attributionSource, inputEvent, null), 3));
    }

    @NotNull
    public com.google.common.util.concurrent.e e(@NotNull androidx.privacysandbox.ads.adservices.measurement.f request) {
        Intrinsics.checkNotNullParameter(request, "request");
        return T1.e(E.f(E.c(O.a), null, new d(this, null), 3));
    }

    @NotNull
    public com.google.common.util.concurrent.e f(@NotNull Uri trigger) {
        Intrinsics.checkNotNullParameter(trigger, "trigger");
        return T1.e(E.f(E.c(O.a), null, new e(this, trigger, null), 3));
    }

    @NotNull
    public com.google.common.util.concurrent.e g(@NotNull androidx.privacysandbox.ads.adservices.measurement.g request) {
        Intrinsics.checkNotNullParameter(request, "request");
        return T1.e(E.f(E.c(O.a), null, new f(this, null), 3));
    }

    @NotNull
    public com.google.common.util.concurrent.e h(@NotNull androidx.privacysandbox.ads.adservices.measurement.h request) {
        Intrinsics.checkNotNullParameter(request, "request");
        return T1.e(E.f(E.c(O.a), null, new g(this, null), 3));
    }
}
