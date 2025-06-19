package com.quizlet.quizletandroid.ui.library.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.library.data.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4648b {
    public final C4647a a;
    public final com.quizlet.ui.models.content.listitem.a b;
    public final long c;

    public C4648b(C4647a cardModel, com.quizlet.ui.models.content.listitem.a contentMetadata) {
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
        if (!(obj instanceof C4648b)) {
            return false;
        }
        C4648b c4648b = (C4648b) obj;
        return Intrinsics.b(this.a, c4648b.a) && Intrinsics.b(this.b, c4648b.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ClassLibraryData(cardModel=" + this.a + ", contentMetadata=" + this.b + ")";
    }
}
