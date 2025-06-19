package com.quizlet.library.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class w implements a {
    public final com.quizlet.ui.models.content.listitem.p a;
    public final String b;

    public w(com.quizlet.ui.models.content.listitem.p contentMetadata) {
        Intrinsics.checkNotNullParameter(contentMetadata, "contentMetadata");
        this.a = contentMetadata;
        this.b = contentMetadata.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof w) && Intrinsics.b(this.a, ((w) obj).a);
    }

    @Override // com.quizlet.library.viewmodels.a
    public final String getKey() {
        return this.b;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "TextbookExpertSolutionData(contentMetadata=" + this.a + ")";
    }
}
