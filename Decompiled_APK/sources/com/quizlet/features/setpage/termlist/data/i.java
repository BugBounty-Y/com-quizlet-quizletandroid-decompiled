package com.quizlet.features.setpage.termlist.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements k {
    public final com.quizlet.features.setpage.termlist.ads.a a;
    public final long b;

    public i(com.quizlet.features.setpage.termlist.ads.a adViewData) {
        Intrinsics.checkNotNullParameter(adViewData, "adViewData");
        this.a = adViewData;
        this.b = adViewData.a.getId();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && Intrinsics.b(this.a, ((i) obj).a);
    }

    @Override // com.quizlet.features.setpage.termlist.data.k
    public final long getId() {
        return this.b;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "AdData(adViewData=" + this.a + ")";
    }
}
