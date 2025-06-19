package com.quizlet.features.questiontypes.mcq.data;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final N2 a;
    public final Y2 b;
    public final boolean c;
    public final com.quizlet.features.questiontypes.basequestion.data.a d;
    public final boolean e;

    public d(N2 promptState, Y2 answerState, boolean z, com.quizlet.features.questiontypes.basequestion.data.a gradedState, boolean z2) {
        Intrinsics.checkNotNullParameter(promptState, "promptState");
        Intrinsics.checkNotNullParameter(answerState, "answerState");
        Intrinsics.checkNotNullParameter(gradedState, "gradedState");
        this.a = promptState;
        this.b = answerState;
        this.c = z;
        this.d = gradedState;
        this.e = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && Intrinsics.b(this.b, dVar.b) && this.c == dVar.c && this.d == dVar.d && this.e == dVar.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + ((this.d.hashCode() + d0.g((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MultipleChoiceQuestionState(promptState=");
        sb.append(this.a);
        sb.append(", answerState=");
        sb.append(this.b);
        sb.append(", audioEnabled=");
        sb.append(this.c);
        sb.append(", gradedState=");
        sb.append(this.d);
        sb.append(", showTryAgain=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
