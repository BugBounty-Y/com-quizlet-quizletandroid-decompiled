package com.quizlet.generated.sharedconfig;

import androidx.compose.animation.d0;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final float a;
    public final String b;
    public final Locale c;

    public a(float f, String family, Locale locale) {
        Intrinsics.checkNotNullParameter(family, "family");
        this.a = f;
        this.b = family;
        this.c = locale;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Float.compare(this.a, aVar.a) == 0 && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        int iE = d0.e(Float.hashCode(this.a) * 31, 31, this.b);
        Locale locale = this.c;
        return iE + (locale == null ? 0 : locale.hashCode());
    }

    public final String toString() {
        return "FontInfo(size=" + this.a + ", family=" + this.b + ", locale=" + this.c + ")";
    }
}
