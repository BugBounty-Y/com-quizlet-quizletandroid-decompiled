package com.quizlet.features.setpage.header.viewmodel;

import androidx.compose.animation.d0;
import com.quizlet.data.model.A0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final androidx.compose.ui.graphics.painter.b a;
    public final String b;
    public final Function0 c;
    public final A0 d;
    public final boolean e;

    public b(androidx.compose.ui.graphics.painter.b icon, String buttonTitle, Function0 onClick, A0 state, boolean z, int i) {
        state = (i & 8) != 0 ? A0.b : state;
        z = (i & 16) != 0 ? false : z;
        Intrinsics.checkNotNullParameter(icon, "icon");
        Intrinsics.checkNotNullParameter(buttonTitle, "buttonTitle");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        Intrinsics.checkNotNullParameter(state, "state");
        this.a = icon;
        this.b = buttonTitle;
        this.c = onClick;
        this.d = state;
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b) && Intrinsics.b(this.c, bVar.c) && this.d == bVar.d && this.e == bVar.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + ((this.d.hashCode() + ((this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ModeButtonDefinition(icon=");
        sb.append(this.a);
        sb.append(", buttonTitle=");
        sb.append(this.b);
        sb.append(", onClick=");
        sb.append(this.c);
        sb.append(", state=");
        sb.append(this.d);
        sb.append(", isDisabled=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
