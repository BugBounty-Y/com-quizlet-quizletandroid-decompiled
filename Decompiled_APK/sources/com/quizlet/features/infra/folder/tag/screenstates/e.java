package com.quizlet.features.infra.folder.tag.screenstates;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements j {
    public final long a;
    public final List b;

    public e(long j, List currentFolderTags) {
        Intrinsics.checkNotNullParameter(currentFolderTags, "currentFolderTags");
        this.a = j;
        this.b = currentFolderTags;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.a == eVar.a && Intrinsics.b(this.b, eVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "Initialize(parentFolderId=" + this.a + ", currentFolderTags=" + this.b + ")";
    }
}
