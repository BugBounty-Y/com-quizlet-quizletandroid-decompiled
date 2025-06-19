package kotlinx.coroutines.channels;

import com.android.billingclient.api.C1472a;
import com.pubmatic.sdk.video.c;
import kotlinx.coroutines.InterfaceC5026k;

/* loaded from: classes3.dex */
public abstract class j {
    public static final p a = new p(-1, null, null, 0);
    public static final int b = kotlinx.coroutines.internal.b.k(32, 12, "kotlinx.coroutines.bufferedChannel.segmentSize");
    public static final int c = kotlinx.coroutines.internal.b.k(c.a.DEFAULT_MEDIA_URI_TIMEOUT, 12, "kotlinx.coroutines.bufferedChannel.expandBufferCompletionWaitIterations");
    public static final C1472a d = new C1472a("BUFFERED", 2);
    public static final C1472a e = new C1472a("SHOULD_BUFFER", 2);
    public static final C1472a f = new C1472a("S_RESUMING_BY_RCV", 2);
    public static final C1472a g = new C1472a("RESUMING_BY_EB", 2);
    public static final C1472a h = new C1472a("POISONED", 2);
    public static final C1472a i = new C1472a("DONE_RCV", 2);
    public static final C1472a j = new C1472a("INTERRUPTED_SEND", 2);
    public static final C1472a k = new C1472a("INTERRUPTED_RCV", 2);
    public static final C1472a l = new C1472a("CHANNEL_CLOSED", 2);
    public static final C1472a m = new C1472a("SUSPEND", 2);
    public static final C1472a n = new C1472a("SUSPEND_NO_WAITER", 2);
    public static final C1472a o = new C1472a("FAILED", 2);
    public static final C1472a p = new C1472a("NO_RECEIVE_RESULT", 2);
    public static final C1472a q = new C1472a("CLOSE_HANDLER_CLOSED", 2);
    public static final C1472a r = new C1472a("CLOSE_HANDLER_INVOKED", 2);
    public static final C1472a s = new C1472a("NO_CLOSE_CAUSE", 2);

    public static final boolean a(InterfaceC5026k interfaceC5026k, Object obj, kotlin.jvm.functions.c cVar) {
        C1472a c1472aK = interfaceC5026k.k(obj, cVar);
        if (c1472aK == null) {
            return false;
        }
        interfaceC5026k.t(c1472aK);
        return true;
    }
}
