package com.quizlet.features.questiontypes.written;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_camera.u3;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends u3 {
    public final String a;
    public final boolean b;
    public final com.quizlet.features.questiontypes.written.data.a c;

    public e(String response, boolean z, com.quizlet.features.questiontypes.written.data.a aVar) {
        Intrinsics.checkNotNullParameter(response, "response");
        this.a = response;
        this.b = z;
        this.c = aVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && this.b == eVar.b && this.c == eVar.c;
    }

    public final int hashCode() {
        int iG = d0.g(this.a.hashCode() * 31, 31, this.b);
        com.quizlet.features.questiontypes.written.data.a aVar = this.c;
        return iG + (aVar == null ? 0 : aVar.hashCode());
    }

    public final String toString() {
        return "TrailingIconClick(response=" + this.a + ", hasFocus=" + this.b + ", userAction=" + this.c + ")";
    }
}
