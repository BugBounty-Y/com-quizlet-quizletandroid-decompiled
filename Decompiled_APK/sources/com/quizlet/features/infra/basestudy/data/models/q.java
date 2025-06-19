package com.quizlet.features.infra.basestudy.data.models;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q implements j {
    public final String a;

    public q(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        this.a = url;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof q) && Intrinsics.b(this.a, ((q) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("StartBlocksMode(url="), this.a, ")");
    }
}
