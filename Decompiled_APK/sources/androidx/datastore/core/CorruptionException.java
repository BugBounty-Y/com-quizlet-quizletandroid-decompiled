package androidx.datastore.core;

import java.io.IOException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class CorruptionException extends IOException {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CorruptionException(String message, int i) {
        super(message, null);
        Intrinsics.checkNotNullParameter(message, "message");
    }
}
