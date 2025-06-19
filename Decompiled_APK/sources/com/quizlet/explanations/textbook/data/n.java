package com.quizlet.explanations.textbook.data;

import androidx.compose.animation.d0;
import com.quizlet.explanations.textbook.exercisedetail.data.ExerciseDetailSetupState;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class n extends p {
    public final ExerciseDetailSetupState a;
    public final boolean b;
    public final boolean c;

    public n(ExerciseDetailSetupState state, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(state, "state");
        this.a = state;
        this.b = z;
        this.c = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.a, nVar.a) && this.b == nVar.b && this.c == nVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Exercise(state=");
        sb.append(this.a);
        sb.append(", addToBackStack=");
        sb.append(this.b);
        sb.append(", clearBackStack=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
