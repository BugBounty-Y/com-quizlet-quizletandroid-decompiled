package com.quizlet.uicommon.ui.common.overflowmenu;

import androidx.compose.animation.d0;
import com.quizlet.data.model.A0;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public final int a;
    public final com.quizlet.qutils.string.f b;
    public final A0 c;
    public final Function0 d;

    public /* synthetic */ f(int i, int i2, Function0 function0) {
        this(i, i2, A0.b, function0);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && Intrinsics.b(this.b, fVar.b) && this.c == fVar.c && Intrinsics.b(this.d, fVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.g((this.c.hashCode() + ((this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31)) * 31, 31, false);
    }

    public final String toString() {
        return "FullscreenOverflowMenuData(iconRes=" + this.a + ", textResData=" + this.b + ", badge=" + this.c + ", shouldTintIcon=false, onClick=" + this.d + ")";
    }

    public f(int i, int i2, A0 badge, Function0 onClick) {
        Intrinsics.checkNotNullParameter(badge, "badge");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        com.quizlet.qutils.string.f textResData = new com.quizlet.qutils.string.f(i2, C4933y.P(args));
        Intrinsics.checkNotNullParameter(textResData, "textResData");
        Intrinsics.checkNotNullParameter(badge, "badge");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        this.a = i;
        this.b = textResData;
        this.c = badge;
        this.d = onClick;
    }
}
