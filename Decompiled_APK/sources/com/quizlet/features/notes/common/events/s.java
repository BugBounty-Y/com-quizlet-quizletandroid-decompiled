package com.quizlet.features.notes.common.events;

import com.quizlet.data.model.R1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s implements y {
    public final R1 a;

    public s(R1 artifact) {
        Intrinsics.checkNotNullParameter(artifact, "artifact");
        this.a = artifact;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof s) && Intrinsics.b(this.a, ((s) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "RefreshArtifactButtonClicked(artifact=" + this.a + ")";
    }
}
