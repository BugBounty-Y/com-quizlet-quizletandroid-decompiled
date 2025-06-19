package com.quizlet.upgrade.data;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C {
    public final List a;
    public final List b;

    public C(List featureList, List footerList) {
        Intrinsics.checkNotNullParameter(featureList, "featureList");
        Intrinsics.checkNotNullParameter(footerList, "footerList");
        this.a = featureList;
        this.b = footerList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C)) {
            return false;
        }
        C c = (C) obj;
        return Intrinsics.b(this.a, c.a) && Intrinsics.b(this.b, c.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "UpgradeFeatureListState(featureList=" + this.a + ", footerList=" + this.b + ")";
    }
}
