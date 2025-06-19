package com.braze.models.response;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f implements d {
    public final com.braze.requests.n a;
    public final com.braze.communication.d b;

    public f(com.braze.requests.n originalRequest, com.braze.communication.d connectionResult) {
        Intrinsics.checkNotNullParameter(originalRequest, "originalRequest");
        Intrinsics.checkNotNullParameter(connectionResult, "connectionResult");
        this.a = originalRequest;
        this.b = connectionResult;
    }

    @Override // com.braze.models.response.d
    public final String a() {
        return "An error occurred during request processing, resulting in no valid response being received. Check the error log for more details.";
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && Intrinsics.b(this.b, fVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (((this.a.hashCode() * 31) - 525898564) * 31);
    }

    public final String toString() {
        return "NetworkCommunicationFailureResponseError(originalRequest=" + this.a + ", errorMessage=An error occurred during request processing, resulting in no valid response being received. Check the error log for more details., connectionResult=" + this.b + ')';
    }
}
