package com.quizlet.features.notes.upload.states;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements e {
    public final String a;
    public final int b;
    public final int c;

    public c(String initialText, int i, int i2) {
        Intrinsics.checkNotNullParameter(initialText, "initialText");
        this.a = initialText;
        this.b = i;
        this.c = i2;
    }

    @Override // com.quizlet.features.notes.upload.states.e
    public final String a() {
        String str = this.a;
        return str == null ? "" : str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && this.b == cVar.b && this.c == cVar.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Idle(initialText=");
        sb.append(this.a);
        sb.append(", maximumCharacter=");
        sb.append(this.b);
        sb.append(", minimumCharacter=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
