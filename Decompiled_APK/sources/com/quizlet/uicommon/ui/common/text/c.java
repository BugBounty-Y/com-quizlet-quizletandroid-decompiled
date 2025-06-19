package com.quizlet.uicommon.ui.common.text;

import androidx.compose.animation.d0;
import com.quizlet.quizletandroid.R;
import com.quizlet.qutils.string.f;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final f a;
    public final Function0 b;

    public c(f resData, Function0 onClick) {
        Intrinsics.checkNotNullParameter(resData, "resData");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        this.a = resData;
        this.b = onClick;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a.equals(cVar.a) && this.b.equals(cVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + d0.b(R.attr.AssemblyLinkTextPressed, d0.b(R.attr.AssemblyLinkText, this.a.hashCode() * 31, 31), 31);
    }

    public final String toString() {
        return "ClickableSubstring(resData=" + this.a + ", defaultColorAttr=2130968634, pressedColorAttr=2130968636, onClick=" + this.b + ")";
    }
}
