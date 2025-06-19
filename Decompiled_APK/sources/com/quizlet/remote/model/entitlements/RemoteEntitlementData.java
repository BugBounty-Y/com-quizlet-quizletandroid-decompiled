package com.quizlet.remote.model.entitlements;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteEntitlementData {
    public final boolean a;
    public final String b;
    public final RemoteMeteringMeta c;
    public final String d;

    public RemoteEntitlementData(boolean z, String str, RemoteMeteringMeta remoteMeteringMeta, String str2) {
        this.a = z;
        this.b = str;
        this.c = remoteMeteringMeta;
        this.d = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteEntitlementData)) {
            return false;
        }
        RemoteEntitlementData remoteEntitlementData = (RemoteEntitlementData) obj;
        return this.a == remoteEntitlementData.a && Intrinsics.b(this.b, remoteEntitlementData.b) && Intrinsics.b(this.c, remoteEntitlementData.c) && Intrinsics.b(this.d, remoteEntitlementData.d);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        RemoteMeteringMeta remoteMeteringMeta = this.c;
        int iHashCode3 = (iHashCode2 + (remoteMeteringMeta == null ? 0 : remoteMeteringMeta.hashCode())) * 31;
        String str2 = this.d;
        return iHashCode3 + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        return "RemoteEntitlementData(canUseFeature=" + this.a + ", overrideReason=" + this.b + ", meteringMeta=" + this.c + ", premiumFeatureIdentifier=" + this.d + ")";
    }
}
