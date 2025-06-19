package com.quizlet.features.notes.detail.events;

import com.quizlet.features.notes.data.z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l implements p {
    public final String a;
    public final z b;

    public l(String noteTitle, z data) {
        Intrinsics.checkNotNullParameter(noteTitle, "noteTitle");
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = noteTitle;
        this.b = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        return Intrinsics.b(this.a, lVar.a) && Intrinsics.b(this.b, lVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Share(noteTitle=" + this.a + ", data=" + this.b + ")";
    }
}
