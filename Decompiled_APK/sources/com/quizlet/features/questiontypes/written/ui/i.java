package com.quizlet.features.questiontypes.written.ui;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final String a;
    public final com.quizlet.qutils.string.g b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final o g;
    public final com.quizlet.features.practicetest.navigation.a h;

    public i(com.quizlet.qutils.string.g placeholder, int i) {
        o oVar = (i & 256) != 0 ? k.b : m.b;
        com.quizlet.features.practicetest.navigation.a onTextChanged = new com.quizlet.features.practicetest.navigation.a(16);
        Intrinsics.checkNotNullParameter("", "text");
        Intrinsics.checkNotNullParameter(placeholder, "placeholder");
        Intrinsics.checkNotNullParameter(onTextChanged, "onTextChanged");
        this.a = "";
        this.b = placeholder;
        this.c = true;
        this.d = true;
        this.e = true;
        this.f = true;
        this.g = oVar;
        this.h = onTextChanged;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return Intrinsics.b(this.a, iVar.a) && Intrinsics.b(this.b, iVar.b) && this.c == iVar.c && this.d == iVar.d && this.e == iVar.e && this.f == iVar.f && Intrinsics.b(this.g, iVar.g) && Intrinsics.b(this.h, iVar.h);
    }

    public final int hashCode() {
        int iG = d0.g(d0.g(d0.g(d0.g(d0.g((this.b.hashCode() + (this.a.hashCode() * 31)) * 961, 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, false);
        o oVar = this.g;
        return this.h.hashCode() + ((iG + (oVar != null ? oVar.hashCode() : 0)) * 31);
    }

    public final String toString() {
        return "WrittenResponseState(text=" + this.a + ", placeholder=" + this.b + ", errorMessage=null, isEnabled=" + this.c + ", isFocused=" + this.d + ", isFocusable=" + this.e + ", isClickable=" + this.f + ", isLoading=false, writtenResponseTrailingIcon=" + this.g + ", onTextChanged=" + this.h + ")";
    }
}
