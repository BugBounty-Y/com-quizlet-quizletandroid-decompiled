package com.braze.events;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class BrazeSdkAuthenticationErrorEvent {
    private final com.braze.models.response.h sdkAuthError;

    public BrazeSdkAuthenticationErrorEvent(com.braze.models.response.h sdkAuthError) {
        Intrinsics.checkNotNullParameter(sdkAuthError, "sdkAuthError");
        this.sdkAuthError = sdkAuthError;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof BrazeSdkAuthenticationErrorEvent) && Intrinsics.b(this.sdkAuthError, ((BrazeSdkAuthenticationErrorEvent) obj).sdkAuthError);
    }

    public int hashCode() {
        return this.sdkAuthError.hashCode();
    }

    public String toString() {
        return this.sdkAuthError.toString();
    }
}
