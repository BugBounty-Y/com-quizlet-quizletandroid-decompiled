package com.quizlet.features.infra.folder.tag.screenstates;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements j {
    public final String a;

    public h(String tagName) {
        Intrinsics.checkNotNullParameter(tagName, "tagName");
        this.a = tagName;
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
        return android.support.v4.media.session.a.t(new StringBuilder("TagNameChanged(tagName="), this.a, ")");
    }
}
