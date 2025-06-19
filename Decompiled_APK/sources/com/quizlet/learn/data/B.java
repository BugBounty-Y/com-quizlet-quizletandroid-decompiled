package com.quizlet.learn.data;

import com.quizlet.ads.data.AdDataType;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class B extends N {
    public final AdDataType a;

    public B(AdDataType adData) {
        Intrinsics.checkNotNullParameter(adData, "adData");
        this.a = adData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof B) && Intrinsics.b(this.a, ((B) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "GoToAdActivity(adData=" + this.a + ")";
    }
}
