package com.quizlet.shared.httpclient.exceptions;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class NetworkErrorException extends Exception {
    public NetworkErrorException() {
        super(null, null);
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof NetworkErrorException)) {
            return false;
        }
        NetworkErrorException networkErrorException = (NetworkErrorException) obj;
        return Intrinsics.b(networkErrorException.getMessage(), getMessage()) && Intrinsics.b(networkErrorException.getCause(), getCause());
    }

    public final int hashCode() {
        return K.a(NetworkErrorException.class).hashCode();
    }
}
