package com.quizlet.explanations.feedback.data;

import com.google.android.gms.internal.mlkit_vision_document_scanner.X6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e extends X6 {
    public final String a;

    public e(String content) {
        Intrinsics.checkNotNullParameter(content, "content");
        this.a = content;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.X6
    public final String b() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof e) && Intrinsics.b(this.a, ((e) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("OtherExplanationsFeedback(content="), this.a, ")");
    }
}
