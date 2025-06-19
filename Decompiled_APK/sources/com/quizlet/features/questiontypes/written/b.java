package com.quizlet.features.questiontypes.written;

import com.google.android.gms.internal.mlkit_vision_camera.u3;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends u3 {
    public final String a;
    public final boolean b;

    public b(String response, boolean z) {
        Intrinsics.checkNotNullParameter(response, "response");
        this.a = response;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && this.b == bVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "AnswerSubmitted(response=" + this.a + ", hasFocus=" + this.b + ")";
    }
}
