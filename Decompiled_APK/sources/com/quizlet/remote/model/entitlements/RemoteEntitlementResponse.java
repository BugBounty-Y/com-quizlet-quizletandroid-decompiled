package com.quizlet.remote.model.entitlements;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteEntitlementResponse {
    public final List a;

    public RemoteEntitlementResponse(List responses) {
        Intrinsics.checkNotNullParameter(responses, "responses");
        this.a = responses;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteEntitlementResponse) && Intrinsics.b(this.a, ((RemoteEntitlementResponse) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("RemoteEntitlementResponse(responses="), this.a);
    }
}
