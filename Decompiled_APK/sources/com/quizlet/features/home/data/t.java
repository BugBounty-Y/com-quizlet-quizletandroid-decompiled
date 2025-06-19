package com.quizlet.features.home.data;

import com.quizlet.data.model.v2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements u {
    public final v2 a;
    public final kotlinx.collections.immutable.b b;

    public t(v2 userProfileAvatarData) {
        kotlinx.collections.immutable.implementations.immutableList.g downloadedSets = kotlinx.collections.immutable.implementations.immutableList.g.c;
        Intrinsics.checkNotNullParameter(userProfileAvatarData, "userProfileAvatarData");
        Intrinsics.checkNotNullParameter(downloadedSets, "downloadedSets");
        this.a = userProfileAvatarData;
        this.b = downloadedSets;
    }

    @Override // com.quizlet.features.home.data.u
    public final v2 a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof t)) {
            return false;
        }
        t tVar = (t) obj;
        return Intrinsics.b(this.a, tVar.a) && Intrinsics.b(this.b, tVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Offline(userProfileAvatarData=" + this.a + ", downloadedSets=" + this.b + ")";
    }
}
