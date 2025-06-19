package com.quizlet.features.notes.common.events;

import com.quizlet.data.model.EssayInfo;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.notes.common.events.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4370a implements y {
    public final EssayInfo a;

    public C4370a(EssayInfo artifact) {
        Intrinsics.checkNotNullParameter(artifact, "artifact");
        this.a = artifact;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4370a) && Intrinsics.b(this.a, ((C4370a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "RefreshArtifactButtonClicked(artifact=" + this.a + ")";
    }
}
