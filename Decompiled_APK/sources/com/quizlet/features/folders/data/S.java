package com.quizlet.features.folders.data;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class S implements T {
    public final List a;

    public S(List items) {
        Intrinsics.checkNotNullParameter(items, "items");
        this.a = items;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof S) && Intrinsics.b(this.a, ((S) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("UpdateStudyMaterialsList(items="), this.a);
    }
}
