package com.quizlet.featuregate.contracts.growthbook;

import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final Object a;

    public a(Map mappings) {
        Intrinsics.checkNotNullParameter(mappings, "mappings");
        this.a = mappings;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.s(new StringBuilder("GrowthBookEnumMappings(mappings="), this.a, ")");
    }
}
