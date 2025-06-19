package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.s0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4306s0 implements InterfaceC4312v0 {
    public final String a;

    public C4306s0(String mediaExerciseId) {
        Intrinsics.checkNotNullParameter(mediaExerciseId, "mediaExerciseId");
        this.a = mediaExerciseId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4306s0) && Intrinsics.b(this.a, ((C4306s0) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("GoToTextbookExercise(mediaExerciseId="), this.a, ")");
    }
}
