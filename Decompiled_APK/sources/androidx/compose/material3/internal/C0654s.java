package androidx.compose.material3.internal;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.internal.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0654s implements Comparable {
    public final int a;
    public final int b;
    public final int c;
    public final long d;

    public C0654s(long j, int i, int i2, int i3) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = j;
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        return Intrinsics.h(this.d, ((C0654s) obj).d);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0654s)) {
            return false;
        }
        C0654s c0654s = (C0654s) obj;
        return this.a == c0654s.a && this.b == c0654s.b && this.c == c0654s.c && this.d == c0654s.d;
    }

    public final int hashCode() {
        return Long.hashCode(this.d) + d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CalendarDate(year=");
        sb.append(this.a);
        sb.append(", month=");
        sb.append(this.b);
        sb.append(", dayOfMonth=");
        sb.append(this.c);
        sb.append(", utcTimeMillis=");
        return d0.q(sb, this.d, ')');
    }
}
