package org.wordpress.aztec.watchers;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_camera.C2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h {
    public final CharSequence a;
    public final int b;
    public CharSequence c;
    public int d;
    public int e;
    public int f;
    public int g;
    public int h;
    public int i;
    public boolean j;
    public int k;
    public int l;

    public h(String textBefore, int i) {
        textBefore = (i & 1) != 0 ? "" : textBefore;
        Intrinsics.checkNotNullParameter(textBefore, "textBefore");
        this.a = textBefore;
        this.b = -1;
        this.c = "";
        int i2 = this.e;
        int i3 = this.f;
        this.g = i2 + i3;
        int i4 = this.d;
        int iAbs = i3 - i4;
        this.h = iAbs;
        int i5 = i4 - i3;
        this.i = i5;
        boolean z = iAbs > i5;
        this.j = z;
        iAbs = z ? iAbs : Math.abs(i5);
        this.k = iAbs;
        this.l = this.j ? this.g - iAbs : this.g + iAbs;
    }

    public final void a() {
        int i = this.e;
        int i2 = this.f;
        this.g = i + i2;
        int i3 = this.d;
        int iAbs = i2 - i3;
        this.h = iAbs;
        int i4 = i3 - i2;
        this.i = i4;
        boolean z = iAbs > i4;
        this.j = z;
        if (!z) {
            iAbs = Math.abs(i4);
        }
        this.k = iAbs;
        this.l = this.j ? this.g - iAbs : this.g + iAbs;
    }

    public final boolean b() {
        int i;
        if (!this.j) {
            return false;
        }
        char cCharAt = this.c.charAt(this.l);
        return cCharAt == '\n' || ((i = this.l - 1) >= 0 && this.c.charAt(i) == '\n' && cCharAt == C2.c);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && this.b == hVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + d0.g(this.a.hashCode() * 31, 31, false);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TextChangedEvent(textBefore=");
        sb.append((Object) this.a);
        sb.append(", deletedFromBlockEnd=false, blockSpanStart=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public h() {
        this(null, 7);
        Intrinsics.checkNotNullParameter("", "text");
        this.c = "";
        this.e = 0;
        this.d = 0;
        this.f = 0;
        a();
    }
}
