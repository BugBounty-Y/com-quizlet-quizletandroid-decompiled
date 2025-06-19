package com.quizlet.features.questiontypes.truefalse;

import com.google.android.gms.internal.mlkit_vision_camera.s3;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p extends s3 {
    public final c a;

    public p(c side) {
        Intrinsics.checkNotNullParameter(side, "side");
        this.a = side;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof p) && this.a == ((p) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "PromptTextClick(side=" + this.a + ")";
    }
}
