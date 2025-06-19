package com.quizlet.remote.model.entitlements;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteEntitlementModels {
    public final List a;

    public RemoteEntitlementModels(List entitlementData) {
        Intrinsics.checkNotNullParameter(entitlementData, "entitlementData");
        this.a = entitlementData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteEntitlementModels) && Intrinsics.b(this.a, ((RemoteEntitlementModels) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("RemoteEntitlementModels(entitlementData="), this.a);
    }
}
