package com.quizlet.upgrade.ui.widgets;

import androidx.compose.animation.d0;
import com.quizlet.qutils.string.f;
import com.quizlet.qutils.string.g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final int a;
    public final f b;
    public final g c;
    public final boolean d;
    public final boolean e;

    public b(int i, f headingStringRes, g infoStringRes, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(headingStringRes, "headingStringRes");
        Intrinsics.checkNotNullParameter(infoStringRes, "infoStringRes");
        this.a = i;
        this.b = headingStringRes;
        this.c = infoStringRes;
        this.d = z;
        this.e = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && this.b.equals(bVar.b) && this.c.equals(bVar.c) && this.d == bVar.d && this.e == bVar.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + d0.g((this.c.hashCode() + ((this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31)) * 31, 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UpgradeTimelineSectionState(iconDrawableRes=");
        sb.append(this.a);
        sb.append(", headingStringRes=");
        sb.append(this.b);
        sb.append(", infoStringRes=");
        sb.append(this.c);
        sb.append(", shouldShowLine=");
        sb.append(this.d);
        sb.append(", isSelected=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
