package androidx.glance.unit;

import android.content.Context;
import androidx.compose.ui.graphics.F;

/* loaded from: classes.dex */
public final class i implements a {
    public final int a;

    public i(int i) {
        this.a = i;
    }

    @Override // androidx.glance.unit.a
    public final long a(Context context) {
        return F.c(b.a.a(context, this.a));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && this.a == ((i) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("ResourceColorProvider(resId="), this.a, ')');
    }
}
