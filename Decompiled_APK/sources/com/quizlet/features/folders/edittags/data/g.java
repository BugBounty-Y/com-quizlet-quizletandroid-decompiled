package com.quizlet.features.folders.edittags.data;

import androidx.compose.animation.d0;
import com.quizlet.data.model.EnumC4159q0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public static final g d = new g("", false, EnumC4159q0.a);
    public final String a;
    public final boolean b;
    public final EnumC4159q0 c;

    public g(String label, boolean z, EnumC4159q0 invalidTagType) {
        Intrinsics.checkNotNullParameter(label, "label");
        Intrinsics.checkNotNullParameter(invalidTagType, "invalidTagType");
        this.a = label;
        this.b = z;
        this.c = invalidTagType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && this.b == gVar.b && this.c == gVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.g(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "EditTagState(label=" + this.a + ", isSaveEnabled=" + this.b + ", invalidTagType=" + this.c + ")";
    }
}
