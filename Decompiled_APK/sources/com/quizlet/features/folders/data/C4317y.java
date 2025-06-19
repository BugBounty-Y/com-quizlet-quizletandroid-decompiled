package com.quizlet.features.folders.data;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.y, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4317y implements T {
    public final List a;

    public C4317y(List tags) {
        Intrinsics.checkNotNullParameter(tags, "tags");
        this.a = tags;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4317y) && Intrinsics.b(this.a, ((C4317y) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("NewTagsAdded(tags="), this.a);
    }
}
