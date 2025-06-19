package com.quizlet.search.data.blended;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends i {
    public final List a;

    public h(List items) {
        Intrinsics.checkNotNullParameter(items, "items");
        this.a = items;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && Intrinsics.b(this.a, ((h) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("MainState(items="), this.a);
    }
}
