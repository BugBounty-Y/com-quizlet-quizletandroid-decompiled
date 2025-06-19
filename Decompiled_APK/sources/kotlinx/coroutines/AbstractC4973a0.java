package kotlinx.coroutines;

import java.io.Closeable;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.coroutines.a0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4973a0 extends AbstractC5040y implements Closeable, AutoCloseable {
    static {
        com.sdk.growthbook.utils.a safeCast = new com.sdk.growthbook.utils.a(21);
        C5039x baseKey = AbstractC5040y.a;
        Intrinsics.checkNotNullParameter(baseKey, "baseKey");
        Intrinsics.checkNotNullParameter(safeCast, "safeCast");
        if (baseKey != null) {
            kotlin.coroutines.l lVar = baseKey.b;
        }
    }
}
