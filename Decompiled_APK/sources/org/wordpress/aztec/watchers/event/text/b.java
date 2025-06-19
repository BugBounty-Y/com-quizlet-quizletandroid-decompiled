package org.wordpress.aztec.watchers.event.text;

import android.text.SpannableStringBuilder;
import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final SpannableStringBuilder a;
    public final int b;
    public final int c;
    public final int d;

    public b(SpannableStringBuilder spannableStringBuilder, int i, int i2, int i3) {
        this.a = spannableStringBuilder;
        this.b = i;
        this.c = i2;
        this.d = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && this.b == bVar.b && this.c == bVar.c && this.d == bVar.d;
    }

    public final int hashCode() {
        SpannableStringBuilder spannableStringBuilder = this.a;
        return Integer.hashCode(this.d) + d0.b(this.c, d0.b(this.b, (spannableStringBuilder == null ? 0 : spannableStringBuilder.hashCode()) * 31, 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BeforeTextChangedEventData(textBefore=");
        sb.append((Object) this.a);
        sb.append(", start=");
        sb.append(this.b);
        sb.append(", count=");
        sb.append(this.c);
        sb.append(", after=");
        return android.support.v4.media.session.a.q(sb, this.d, ')');
    }
}
