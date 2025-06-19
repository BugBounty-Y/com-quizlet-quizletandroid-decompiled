package androidx.appcompat.app;

import android.app.Activity;
import android.window.OnBackInvokedCallback;
import android.window.OnBackInvokedDispatcher;
import java.util.Objects;

/* loaded from: classes.dex */
public abstract class v {
    public static OnBackInvokedDispatcher a(Activity activity) {
        return activity.getOnBackInvokedDispatcher();
    }

    public static OnBackInvokedCallback b(Object obj, B b) {
        Objects.requireNonNull(b);
        androidx.activity.G g = new androidx.activity.G(b, 1);
        androidx.activity.t.u(obj).registerOnBackInvokedCallback(1000000, g);
        return g;
    }

    public static void c(Object obj, Object obj2) {
        androidx.activity.t.u(obj).unregisterOnBackInvokedCallback(androidx.activity.t.r(obj2));
    }
}
