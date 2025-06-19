package com.quizlet.features.notes.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements x {
    public final String a;

    public m(String fileSize) {
        Intrinsics.checkNotNullParameter(fileSize, "fileSize");
        this.a = fileSize;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && Intrinsics.b(this.a, ((m) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("MaximumFileSize(fileSize="), this.a, ")");
    }
}
