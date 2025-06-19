package androidx.privacysandbox.ads.adservices.topics;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class g extends i {
    public g(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Object systemService = context.getSystemService((Class<Object>) android.adservices.topics.a.class);
        Intrinsics.checkNotNullExpressionValue(systemService, "context.getSystemService…opicsManager::class.java)");
        if (systemService != null) {
            throw new ClassCastException();
        }
        throw null;
    }

    @Override // androidx.privacysandbox.ads.adservices.topics.i
    public final void a(a request) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(request, "request");
        throw new RuntimeException("Stub!");
    }
}
