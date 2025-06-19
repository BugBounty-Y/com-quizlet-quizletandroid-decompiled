package leakcanary;

import android.os.Handler;
import android.os.HandlerThread;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class f extends kotlin.jvm.internal.r implements Function0 {
    public static final f a = new f(0);

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        HandlerThread handlerThread = new HandlerThread("plumber-android-leaks");
        handlerThread.start();
        return new Handler(handlerThread.getLooper());
    }
}
