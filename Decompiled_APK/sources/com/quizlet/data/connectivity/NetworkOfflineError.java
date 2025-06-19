package com.quizlet.data.connectivity;

import java.net.UnknownHostException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class NetworkOfflineError extends UnknownHostException {
    public NetworkOfflineError() {
        this(0);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public NetworkOfflineError(int i) {
        super("offline");
        Intrinsics.checkNotNullParameter("offline", "message");
    }
}
