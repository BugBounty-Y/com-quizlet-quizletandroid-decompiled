package androidx.camera.core;

import com.appsflyer.internal.AFc1eSDK;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;

/* renamed from: androidx.camera.core.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RejectedExecutionHandlerC0189l implements RejectedExecutionHandler {
    public final /* synthetic */ int a;

    public /* synthetic */ RejectedExecutionHandlerC0189l(int i) {
        this.a = i;
    }

    @Override // java.util.concurrent.RejectedExecutionHandler
    public final void rejectedExecution(Runnable runnable, ThreadPoolExecutor threadPoolExecutor) throws InterruptedException {
        switch (this.a) {
            case 0:
                AbstractC3053s1.c("CameraExecutor", "A rejected execution occurred in CameraExecutor!");
                break;
            default:
                AFc1eSDK.getMediationNetwork(runnable, threadPoolExecutor);
                break;
        }
    }
}
