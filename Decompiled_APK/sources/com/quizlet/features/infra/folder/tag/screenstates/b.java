package com.quizlet.features.infra.folder.tag.screenstates;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements c {
    public final long a;
    public final List b;

    public b(long j, List tags) {
        Intrinsics.checkNotNullParameter(tags, "tags");
        this.a = j;
        this.b = tags;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "SavedTags(parentFolderId=" + this.a + ", tags=" + this.b + ")";
    }
}
