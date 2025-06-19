package io.ktor.utils.io;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class ConcurrentIOException extends IllegalStateException {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ConcurrentIOException(String taskName) {
        super("Concurrent " + taskName + " attempts");
        Intrinsics.checkNotNullParameter(taskName, "taskName");
    }
}
