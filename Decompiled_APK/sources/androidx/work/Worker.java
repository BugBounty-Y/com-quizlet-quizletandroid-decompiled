package androidx.work;

import android.content.Context;
import androidx.camera.camera2.internal.C0143u;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.concurrent.Executor;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public abstract class Worker extends y {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Worker(@NotNull Context context, @NotNull WorkerParameters workerParams) {
        super(context, workerParams);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(workerParams, "workerParams");
    }

    public abstract x doWork();

    @NotNull
    public C1442p getForegroundInfo() {
        throw new IllegalStateException("Expedited WorkRequests require a Worker to provide an implementation for `getForegroundInfo()`");
    }

    @Override // androidx.work.y
    @NotNull
    public com.google.common.util.concurrent.e getForegroundInfoAsync() {
        Executor backgroundExecutor = getBackgroundExecutor();
        Intrinsics.checkNotNullExpressionValue(backgroundExecutor, "backgroundExecutor");
        androidx.concurrent.futures.l lVarB = Y5.b(new C0143u(backgroundExecutor, new S(this, 0)));
        Intrinsics.checkNotNullExpressionValue(lVarB, "getFuture {\n        val …        }\n        }\n    }");
        return lVarB;
    }

    @Override // androidx.work.y
    @NotNull
    public final com.google.common.util.concurrent.e startWork() {
        Executor backgroundExecutor = getBackgroundExecutor();
        Intrinsics.checkNotNullExpressionValue(backgroundExecutor, "backgroundExecutor");
        androidx.concurrent.futures.l lVarB = Y5.b(new C0143u(backgroundExecutor, new S(this, 1)));
        Intrinsics.checkNotNullExpressionValue(lVarB, "getFuture {\n        val …        }\n        }\n    }");
        return lVarB;
    }
}
