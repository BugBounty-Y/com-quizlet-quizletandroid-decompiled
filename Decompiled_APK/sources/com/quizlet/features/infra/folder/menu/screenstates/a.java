package com.quizlet.features.infra.folder.menu.screenstates;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final long a;
    public final List b;

    public a(long j, List currentFolderTags) {
        Intrinsics.checkNotNullParameter(currentFolderTags, "currentFolderTags");
        this.a = j;
        this.b = currentFolderTags;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "AddTagEvent(parentFolderId=" + this.a + ", currentFolderTags=" + this.b + ")";
    }
}
