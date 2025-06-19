package com.quizlet.quizletandroid.ui.widgets.ui.theme;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final com.quizlet.themes.b a;
    public final com.quizlet.themes.b b;

    public b(com.quizlet.themes.b day, com.quizlet.themes.b night) {
        Intrinsics.checkNotNullParameter(day, "day");
        Intrinsics.checkNotNullParameter(night, "night");
        this.a = day;
        this.b = night;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ColorThemes(day=" + this.a + ", night=" + this.b + ")";
    }
}
