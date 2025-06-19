package com.quizlet.features.infra.basestudy.data.models;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p implements j {
    public final String a;

    public p(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        this.a = url;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof p) && Intrinsics.b(this.a, ((p) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("StartBlastMode(url="), this.a, ")");
    }
}
