package androidx.lifecycle;

import android.app.Application;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.lifecycle.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1237a extends w0 {
    public final Application b;

    public AbstractC1237a(Application application) {
        Intrinsics.checkNotNullParameter(application, "application");
        this.b = application;
    }

    public final Application A() {
        Application application = this.b;
        Intrinsics.e(application, "null cannot be cast to non-null type T of androidx.lifecycle.AndroidViewModel.getApplication");
        return application;
    }
}
