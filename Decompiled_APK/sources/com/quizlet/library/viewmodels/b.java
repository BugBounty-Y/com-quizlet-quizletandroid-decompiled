package com.quizlet.library.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements a {
    public final com.quizlet.ui.models.content.listitem.c a;
    public final String b;

    public b(com.quizlet.ui.models.content.listitem.c contentMetadata) {
        Intrinsics.checkNotNullParameter(contentMetadata, "contentMetadata");
        this.a = contentMetadata;
        this.b = contentMetadata.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    @Override // com.quizlet.library.viewmodels.a
    public final String getKey() {
        return this.b;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ExplanationQuestionExpertSolutionData(contentMetadata=" + this.a + ")";
    }
}
