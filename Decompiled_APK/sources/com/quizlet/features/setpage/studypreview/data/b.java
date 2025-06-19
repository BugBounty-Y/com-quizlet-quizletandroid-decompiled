package com.quizlet.features.setpage.studypreview.data;

import androidx.compose.animation.d0;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final ArrayList a;
    public final boolean b;
    public final long c;

    public b(ArrayList flashcards, boolean z, long j) {
        Intrinsics.checkNotNullParameter(flashcards, "flashcards");
        this.a = flashcards;
        this.b = z;
        this.c = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a.equals(bVar.a) && this.b == bVar.b && this.c == bVar.c;
    }

    public final int hashCode() {
        return Long.hashCode(this.c) + d0.g(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudyPreviewData(flashcards=");
        sb.append(this.a);
        sb.append(", isSelectedTermsOnly=");
        sb.append(this.b);
        sb.append(", localSetId=");
        return android.support.v4.media.session.a.g(this.c, ")", sb);
    }
}
