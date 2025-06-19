package com.quizlet.features.questiontypes.written;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3455g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q extends r {
    public final com.quizlet.features.questiontypes.written.data.g a;
    public final AbstractC3455g b;
    public final com.quizlet.features.questiontypes.basequestion.data.a c;
    public final boolean d;
    public final com.quizlet.features.questiontypes.composables.d e;
    public final com.quizlet.features.questiontypes.composables.d f;

    public q(com.quizlet.features.questiontypes.written.data.g writtenState, AbstractC3455g gradingState, com.quizlet.features.questiontypes.basequestion.data.a gradedState, boolean z, com.quizlet.features.questiontypes.composables.d dVar, com.quizlet.features.questiontypes.composables.d dVar2) {
        Intrinsics.checkNotNullParameter(writtenState, "writtenState");
        Intrinsics.checkNotNullParameter(gradingState, "gradingState");
        Intrinsics.checkNotNullParameter(gradedState, "gradedState");
        this.a = writtenState;
        this.b = gradingState;
        this.c = gradedState;
        this.d = z;
        this.e = dVar;
        this.f = dVar2;
    }

    public static q a(q qVar, AbstractC3455g gradingState, com.quizlet.features.questiontypes.basequestion.data.a gradedState, com.quizlet.features.questiontypes.composables.d dVar, com.quizlet.features.questiontypes.composables.d dVar2) {
        com.quizlet.features.questiontypes.written.data.g writtenState = qVar.a;
        Intrinsics.checkNotNullParameter(writtenState, "writtenState");
        Intrinsics.checkNotNullParameter(gradingState, "gradingState");
        Intrinsics.checkNotNullParameter(gradedState, "gradedState");
        return new q(writtenState, gradingState, gradedState, qVar.d, dVar, dVar2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return Intrinsics.b(this.a, qVar.a) && Intrinsics.b(this.b, qVar.b) && this.c == qVar.c && this.d == qVar.d && Intrinsics.b(this.e, qVar.e) && Intrinsics.b(this.f, qVar.f);
    }

    public final int hashCode() {
        int iG = d0.g((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31, 31, this.d);
        com.quizlet.features.questiontypes.composables.d dVar = this.e;
        int iHashCode = (iG + (dVar == null ? 0 : dVar.hashCode())) * 31;
        com.quizlet.features.questiontypes.composables.d dVar2 = this.f;
        return iHashCode + (dVar2 != null ? dVar2.hashCode() : 0);
    }

    public final String toString() {
        return "ViewState(writtenState=" + this.a + ", gradingState=" + this.b + ", gradedState=" + this.c + ", showTryAgain=" + this.d + ", primaryContinueState=" + this.e + ", secondaryContinueState=" + this.f + ")";
    }
}
