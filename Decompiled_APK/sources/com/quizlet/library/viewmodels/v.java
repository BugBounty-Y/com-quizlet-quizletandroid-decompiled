package com.quizlet.library.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class v implements a {
    public final com.quizlet.ui.models.content.listitem.q a;
    public final String b;

    public v(com.quizlet.ui.models.content.listitem.q contentMetadata) {
        Intrinsics.checkNotNullParameter(contentMetadata, "contentMetadata");
        this.a = contentMetadata;
        this.b = contentMetadata.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof v) && Intrinsics.b(this.a, ((v) obj).a);
    }

    @Override // com.quizlet.library.viewmodels.a
    public final String getKey() {
        return this.b;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "TextbookExerciseExpertSolutionData(contentMetadata=" + this.a + ")";
    }
}
