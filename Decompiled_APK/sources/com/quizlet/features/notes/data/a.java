package com.quizlet.features.notes.data;

import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final androidx.compose.ui.graphics.painter.b a;

    public a(androidx.compose.ui.graphics.painter.b icon) {
        Intrinsics.checkNotNullParameter(icon, "icon");
        this.a = icon;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof a) {
            return Intrinsics.b(this.a, ((a) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(R.string.magic_notes_sample_essay) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ArtifactHeaderData(icon=" + this.a + ", artifactName=2132018805)";
    }
}
