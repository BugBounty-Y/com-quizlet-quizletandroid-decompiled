package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4288j implements InterfaceC4315x {
    public final String a;
    public final int b;
    public final boolean c;

    public C4288j(String exerciseId, int i, boolean z) {
        Intrinsics.checkNotNullParameter(exerciseId, "exerciseId");
        this.a = exerciseId;
        this.b = i;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4288j)) {
            return false;
        }
        C4288j c4288j = (C4288j) obj;
        return Intrinsics.b(this.a, c4288j.a) && this.b == c4288j.b && this.c == c4288j.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExerciseClicked(exerciseId=");
        sb.append(this.a);
        sb.append(", index=");
        sb.append(this.b);
        sb.append(", isRecommended=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
