package com.quizlet.features.setpage.screenstates;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements v {
    public final List a;

    public t(List items) {
        Intrinsics.checkNotNullParameter(items, "items");
        this.a = items;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof t) && Intrinsics.b(this.a, ((t) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("Loaded(items="), this.a);
    }
}
