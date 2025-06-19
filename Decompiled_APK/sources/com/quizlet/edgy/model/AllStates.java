package com.quizlet.edgy.model;

import com.squareup.moshi.m;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class AllStates {
    public final Map a;

    public AllStates(Map allStates) {
        Intrinsics.checkNotNullParameter(allStates, "allStates");
        this.a = allStates;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof AllStates) && Intrinsics.b(this.a, ((AllStates) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "AllStates(allStates=" + this.a + ")";
    }
}
