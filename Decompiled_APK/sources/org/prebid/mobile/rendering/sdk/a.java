package org.prebid.mobile.rendering.sdk;

import android.os.Handler;
import android.os.Looper;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.api.data.InitializationStatus;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ InitializationNotifier b;
    public final /* synthetic */ String c;

    public /* synthetic */ a(InitializationNotifier initializationNotifier, String str, int i) {
        this.a = i;
        this.b = initializationNotifier;
        this.c = str;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                InitializationNotifier initializationNotifier = this.b;
                initializationNotifier.getClass();
                String str = this.c;
                LogUtil.a(str);
                com.quizlet.infra.legacysyncengine.models.serializers.a aVar = initializationNotifier.a;
                if (aVar != null) {
                    InitializationStatus initializationStatus = InitializationStatus.d;
                    initializationStatus.a = str;
                    aVar.f(initializationStatus);
                }
                PrebidContextHolder.a = null;
                initializationNotifier.a = null;
                InitializationNotifier.c = false;
                break;
            case 1:
                InitializationNotifier initializationNotifier2 = this.b;
                String str2 = this.c;
                if (str2 == null) {
                    LogUtil.e(3, "InitializationNotifier", "Prebid SDK 3.0.0 initialized");
                    if (initializationNotifier2.a != null) {
                        new Handler(Looper.getMainLooper()).post(new b(initializationNotifier2, 0));
                    }
                } else {
                    LogUtil.b("InitializationNotifier", str2);
                    if (initializationNotifier2.a != null) {
                        new Handler(Looper.getMainLooper()).post(new a(initializationNotifier2, str2, 2));
                    }
                }
                InitializationNotifier.b = true;
                InitializationNotifier.c = false;
                break;
            default:
                InitializationNotifier initializationNotifier3 = this.b;
                InitializationStatus initializationStatus2 = InitializationStatus.c;
                initializationStatus2.a = this.c;
                initializationNotifier3.a.f(initializationStatus2);
                initializationNotifier3.a = null;
                break;
        }
    }
}
