package com.quizlet.edgy.model;

import com.squareup.moshi.m;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class AllCountries {
    public final Map a;

    public AllCountries(Map allCountries) {
        Intrinsics.checkNotNullParameter(allCountries, "allCountries");
        this.a = allCountries;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof AllCountries) && Intrinsics.b(this.a, ((AllCountries) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "AllCountries(allCountries=" + this.a + ")";
    }
}
