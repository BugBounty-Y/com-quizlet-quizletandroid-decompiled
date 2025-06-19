package androidx.glance.unit;

import android.content.Context;
import androidx.compose.ui.graphics.C0861v;
import kotlin.C;
import kotlin.D;

/* loaded from: classes.dex */
public final class h implements a {
    public final long a;

    public h(long j) {
        this.a = j;
    }

    @Override // androidx.glance.unit.a
    public final long a(Context context) {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && C0861v.c(this.a, ((h) obj).a);
    }

    public final int hashCode() {
        int i = C0861v.h;
        C c = D.b;
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return "FixedColorProvider(color=" + ((Object) C0861v.i(this.a)) + ')';
    }
}
