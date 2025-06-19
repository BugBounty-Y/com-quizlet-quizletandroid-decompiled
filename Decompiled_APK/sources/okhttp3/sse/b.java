package okhttp3.sse;

import kotlin.jvm.internal.Intrinsics;
import okhttp3.H;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public abstract class b {
    public abstract void onClosed(a aVar);

    public abstract void onEvent(a aVar, String str, String str2, String str3);

    public void onFailure(@NotNull a eventSource, Throwable th, H h) {
        Intrinsics.checkNotNullParameter(eventSource, "eventSource");
    }

    public void onOpen(@NotNull a eventSource, @NotNull H response) {
        Intrinsics.checkNotNullParameter(eventSource, "eventSource");
        Intrinsics.checkNotNullParameter(response, "response");
    }
}
