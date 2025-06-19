package com.quizlet.features.infra.folder.create.coursefolder.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements j {
    public final String a;

    public f(String folderTitle) {
        Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
        this.a = folderTitle;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && Intrinsics.b(this.a, ((f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("FolderTitleChanged(folderTitle="), this.a, ")");
    }
}
