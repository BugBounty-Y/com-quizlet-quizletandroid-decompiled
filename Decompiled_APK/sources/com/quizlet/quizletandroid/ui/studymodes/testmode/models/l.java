package com.quizlet.quizletandroid.ui.studymodes.testmode.models;

import com.google.android.gms.internal.mlkit_vision_document_scanner.e7;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l extends e7 {
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f b;
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f c;

    public l(com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f expectedAnswer, com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f submittedAnswer) {
        Intrinsics.checkNotNullParameter(expectedAnswer, "expectedAnswer");
        Intrinsics.checkNotNullParameter(submittedAnswer, "submittedAnswer");
        this.b = expectedAnswer;
        this.c = submittedAnswer;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.e7
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f a() {
        return this.b;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.e7
    public final com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f b() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        return Intrinsics.b(this.b, lVar.b) && Intrinsics.b(this.c, lVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + (this.b.hashCode() * 31);
    }

    public final String toString() {
        return "Default(expectedAnswer=" + this.b + ", submittedAnswer=" + this.c + ")";
    }
}
