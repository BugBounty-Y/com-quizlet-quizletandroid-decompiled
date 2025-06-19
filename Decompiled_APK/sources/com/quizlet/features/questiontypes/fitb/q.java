package com.quizlet.features.questiontypes.fitb;

import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q extends Q2 {
    public final String a;

    public q(String answer) {
        Intrinsics.checkNotNullParameter(answer, "answer");
        this.a = answer;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof q) && Intrinsics.b(this.a, ((q) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("SubmitAnswer(answer="), this.a, ")");
    }
}
