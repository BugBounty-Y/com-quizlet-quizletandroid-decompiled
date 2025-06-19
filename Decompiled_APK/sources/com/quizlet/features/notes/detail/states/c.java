package com.quizlet.features.notes.detail.states;

import androidx.compose.animation.d0;
import com.quizlet.data.model.R1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements d {
    public final R1 a;
    public final String b;

    public c(R1 artifact, String str) {
        Intrinsics.checkNotNullParameter(artifact, "artifact");
        this.a = artifact;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return Boolean.hashCode(false) + d0.g((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31, false);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Success(artifact=");
        sb.append(this.a);
        sb.append(", title=");
        return android.support.v4.media.session.a.t(sb, this.b, ", shouldShowOnboarding=false, isUserCreator=false)");
    }
}
