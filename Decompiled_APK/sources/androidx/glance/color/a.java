package androidx.glance.color;

import android.content.Context;
import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.C0861v;
import kotlin.C;
import kotlin.D;

/* loaded from: classes.dex */
public final class a implements androidx.glance.unit.a {
    public final long a;
    public final long b;

    public a(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    @Override // androidx.glance.unit.a
    public final long a(Context context) {
        return (context.getResources().getConfiguration().uiMode & 48) == 32 ? this.b : this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return C0861v.c(this.a, aVar.a) && C0861v.c(this.b, aVar.b);
    }

    public final int hashCode() {
        int i = C0861v.h;
        C c = D.b;
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DayNightColorProvider(day=");
        d0.x(this.a, ", night=", sb);
        sb.append((Object) C0861v.i(this.b));
        sb.append(')');
        return sb.toString();
    }
}
