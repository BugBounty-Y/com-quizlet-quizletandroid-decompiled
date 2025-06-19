package com.quizlet.features.questiontypes.truefalse;

import com.google.android.gms.internal.mlkit_vision_camera.s3;

/* loaded from: classes3.dex */
public final class q extends s3 {
    public final boolean a;

    public q(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof q) && this.a == ((q) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("SubmitAnswer(answer="), this.a);
    }
}
