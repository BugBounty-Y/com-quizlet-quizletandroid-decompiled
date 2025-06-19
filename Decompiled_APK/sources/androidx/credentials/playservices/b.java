package androidx.credentials.playservices;

import android.os.CancellationSignal;
import android.util.Log;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public static boolean a(CancellationSignal cancellationSignal) {
        if (cancellationSignal == null) {
            Log.i("PlayServicesImpl", "No cancellationSignal found");
            return false;
        }
        if (!cancellationSignal.isCanceled()) {
            return false;
        }
        Log.i("PlayServicesImpl", "the flow has been canceled");
        return true;
    }

    public static void b(CancellationSignal cancellationSignal, Function0 callback) {
        Intrinsics.checkNotNullParameter(callback, "callback");
        if (a(cancellationSignal)) {
            return;
        }
        callback.invoke();
    }
}
