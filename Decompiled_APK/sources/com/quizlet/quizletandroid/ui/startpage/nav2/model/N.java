package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3603d6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class N extends AbstractC3603d6 {
    public final String a;

    public N(String sourceName) {
        Intrinsics.checkNotNullParameter(sourceName, "sourceName");
        this.a = sourceName;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3603d6
    public final String c() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof N) && Intrinsics.b(this.a, ((N) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("SchoolSourceRecommendation(sourceName="), this.a, ")");
    }
}
