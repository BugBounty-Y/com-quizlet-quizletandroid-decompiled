package com.quizlet.features.infra.folder.tag.screenstates;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements j {
    public final String a;
    public final boolean b;

    public d(String tagName, boolean z) {
        Intrinsics.checkNotNullParameter(tagName, "tagName");
        this.a = tagName;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && this.b == dVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AddTagClicked(tagName=");
        sb.append(this.a);
        sb.append(", recommendedTag=");
        return android.support.v4.media.session.a.o(")", sb, this.b);
    }
}
