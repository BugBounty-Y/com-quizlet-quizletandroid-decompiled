package androidx.work.rxjava3;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.C0143u;
import androidx.camera.core.impl.utils.executor.a;
import androidx.work.WorkerParameters;
import androidx.work.y;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import com.google.common.util.concurrent.e;
import io.reactivex.rxjava3.core.p;

/* loaded from: classes.dex */
public abstract class RxWorker extends y {
    public static final a e = new a(2);

    public RxWorker(@NonNull Context context, @NonNull WorkerParameters workerParameters) {
        super(context, workerParameters);
    }

    public abstract p a();

    @Override // androidx.work.y
    public final e getForegroundInfoAsync() {
        return Y5.b(new C0143u(14, this, p.d(new IllegalStateException("Expedited WorkRequests require a RxWorker to provide an implementation for `getForegroundInfo()`"))));
    }

    @Override // androidx.work.y
    public final e startWork() {
        return Y5.b(new C0143u(14, this, a()));
    }
}
