package com.quizlet.quizletandroid.ui.library.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.library.data.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4649c {
    public final com.quizlet.ui.models.content.carditem.c a;
    public final com.quizlet.ui.models.content.listitem.e b;
    public final long c;

    public C4649c(com.quizlet.ui.models.content.carditem.c cardModel, com.quizlet.ui.models.content.listitem.e contentMetadata) {
        Intrinsics.checkNotNullParameter(cardModel, "cardModel");
        Intrinsics.checkNotNullParameter(contentMetadata, "contentMetadata");
        this.a = cardModel;
        this.b = contentMetadata;
        this.c = contentMetadata.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4649c)) {
            return false;
        }
        C4649c c4649c = (C4649c) obj;
        return Intrinsics.b(this.a, c4649c.a) && Intrinsics.b(this.b, c4649c.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "FolderLibraryData(cardModel=" + this.a + ", contentMetadata=" + this.b + ")";
    }
}
