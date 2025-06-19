package com.quizlet.library.data;

import com.quizlet.ui.models.content.listitem.f;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements d {
    public final a a;
    public final f b;

    public b(a noteData, f contentMetadata) {
        Intrinsics.checkNotNullParameter(noteData, "noteData");
        Intrinsics.checkNotNullParameter(contentMetadata, "contentMetadata");
        this.a = noteData;
        this.b = contentMetadata;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    @Override // com.quizlet.library.data.d
    public final String getKey() {
        return this.a.a;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Card(noteData=" + this.a + ", contentMetadata=" + this.b + ")";
    }
}
