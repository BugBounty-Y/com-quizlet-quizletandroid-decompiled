package com.quizlet.features.infra.basestudy.data.models;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements w {
    public final List a;

    public a(List setIds) {
        Intrinsics.checkNotNullParameter(setIds, "setIds");
        this.a = setIds;
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
        return android.support.v4.media.session.a.n(")", new StringBuilder("AddSetToClass(setIds="), this.a);
    }
}
