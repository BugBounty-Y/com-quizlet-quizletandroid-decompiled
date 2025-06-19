package com.quizlet.features.questiontypes.fitb;

import androidx.compose.animation.core.J0;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public final N2 a;
    public final kotlinx.collections.immutable.b b;
    public final J0 c;
    public final com.quizlet.features.questiontypes.basequestion.data.a d;
    public final com.quizlet.features.questiontypes.composables.d e;
    public final com.quizlet.features.questiontypes.composables.d f;

    public g(N2 prompt, kotlinx.collections.immutable.b segments, J0 answerState, com.quizlet.features.questiontypes.basequestion.data.a gradedState, com.quizlet.features.questiontypes.composables.d dVar, com.quizlet.features.questiontypes.composables.d dVar2) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(segments, "segments");
        Intrinsics.checkNotNullParameter(answerState, "answerState");
        Intrinsics.checkNotNullParameter(gradedState, "gradedState");
        this.a = prompt;
        this.b = segments;
        this.c = answerState;
        this.d = gradedState;
        this.e = dVar;
        this.f = dVar2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && Intrinsics.b(this.b, gVar.b) && Intrinsics.b(this.c, gVar.c) && this.d == gVar.d && Intrinsics.b(this.e, gVar.e) && Intrinsics.b(this.f, gVar.f);
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31;
        com.quizlet.features.questiontypes.composables.d dVar = this.e;
        int iHashCode2 = (iHashCode + (dVar == null ? 0 : dVar.hashCode())) * 31;
        com.quizlet.features.questiontypes.composables.d dVar2 = this.f;
        return iHashCode2 + (dVar2 != null ? dVar2.hashCode() : 0);
    }

    public final String toString() {
        return "FillInTheBlankUiState(prompt=" + this.a + ", segments=" + this.b + ", answerState=" + this.c + ", gradedState=" + this.d + ", primaryContinueState=" + this.e + ", secondaryContinueState=" + this.f + ")";
    }
}
