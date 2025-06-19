package leakcanary;

import android.app.Application;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x implements curtains.c {
    public final /* synthetic */ Application a;

    public x(Application application) {
        this.a = application;
    }

    @Override // curtains.c
    public final void a(View it2, boolean z) {
        Intrinsics.f(it2, "view");
        Intrinsics.checkNotNullParameter(it2, "view");
        if (z) {
            return;
        }
        Intrinsics.f(it2, "it");
        kotlin.u uVar = leakcanary.internal.d.a;
        Looper mainLooper = Looper.getMainLooper();
        Intrinsics.c(mainLooper, "Looper.getMainLooper()");
        if (mainLooper.getThread() == Thread.currentThread()) {
            y.a(this.a);
        } else {
            ((Handler) leakcanary.internal.d.a.getValue()).post(new com.google.android.gms.common.api.internal.w(this, 22));
        }
    }
}
