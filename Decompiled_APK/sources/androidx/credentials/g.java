package androidx.credentials;

import android.content.Context;
import android.os.CancellationSignal;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public interface g {
    boolean isAvailableOnDevice();

    void onClearCredential(a aVar, CancellationSignal cancellationSignal, Executor executor, e eVar);

    void onGetCredential(Context context, o oVar, CancellationSignal cancellationSignal, Executor executor, e eVar);
}
