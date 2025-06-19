package org.prebid.mobile.rendering.sdk;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import androidx.camera.camera2.internal.RunnableC0131h;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.prebid.mobile.api.data.InitializationStatus;
import org.prebid.mobile.rendering.sdk.SdkInitializer;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ InitializationNotifier b;

    public /* synthetic */ b(InitializationNotifier initializationNotifier, int i) {
        this.a = i;
        this.b = initializationNotifier;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                InitializationNotifier initializationNotifier = this.b;
                initializationNotifier.a.f(InitializationStatus.b);
                initializationNotifier.a = null;
                break;
            default:
                InitializationNotifier initializationNotifier2 = this.b;
                ExecutorService executorServiceNewFixedThreadPool = Executors.newFixedThreadPool(2);
                try {
                    Future futureSubmit = executorServiceNewFixedThreadPool.submit(new StatusRequester());
                    executorServiceNewFixedThreadPool.execute(new SdkInitializer.UserConsentFetcherTask());
                    executorServiceNewFixedThreadPool.execute(new UserAgentFetcherTask());
                    executorServiceNewFixedThreadPool.execute(new RunnableC0131h(26));
                    executorServiceNewFixedThreadPool.shutdown();
                    if (executorServiceNewFixedThreadPool.awaitTermination(10L, TimeUnit.SECONDS)) {
                        new Handler(Looper.getMainLooper()).post(new a(initializationNotifier2, (String) futureSubmit.get(), 1));
                    } else {
                        new Handler(Looper.getMainLooper()).post(new a(initializationNotifier2, "Terminated by timeout.", 0));
                    }
                    break;
                } catch (Exception e) {
                    new Handler(Looper.getMainLooper()).post(new a(initializationNotifier2, "Exception during initialization: " + Log.getStackTraceString(e), 0));
                    return;
                }
        }
    }
}
