package com.quizlet.remote.model.entitlements;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class EntitlementResponse {
    public final RemoteEntitlementModels a;

    public EntitlementResponse(RemoteEntitlementModels models) {
        Intrinsics.checkNotNullParameter(models, "models");
        this.a = models;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof EntitlementResponse) && Intrinsics.b(this.a, ((EntitlementResponse) obj).a);
    }

    public final int hashCode() {
        return this.a.a.hashCode();
    }

    public final String toString() {
        return "EntitlementResponse(models=" + this.a + ")";
    }
}
