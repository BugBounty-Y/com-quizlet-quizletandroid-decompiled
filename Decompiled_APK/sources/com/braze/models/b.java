package com.braze.models;

import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements k {
    public final LinkedHashSet a;
    public final boolean b;

    public b(LinkedHashSet eventsList) {
        Intrinsics.checkNotNullParameter(eventsList, "eventsList");
        this.a = eventsList;
        this.b = eventsList.isEmpty();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    @Override // com.braze.models.k
    public final boolean isEmpty() {
        return this.b;
    }

    public final String toString() {
        return "BrazeEventContainer(eventsList=" + this.a + ')';
    }
}
