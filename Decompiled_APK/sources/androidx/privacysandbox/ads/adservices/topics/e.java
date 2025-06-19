package androidx.privacysandbox.ads.adservices.topics;

import android.content.Context;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class e extends i {
    public e(@NotNull Context context) {
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

    @Override // androidx.privacysandbox.ads.adservices.topics.i
    public final b b() {
        Intrinsics.checkNotNullParameter(null, "response");
        Intrinsics.checkNotNullParameter(null, "response");
        new ArrayList();
        throw null;
    }
}
