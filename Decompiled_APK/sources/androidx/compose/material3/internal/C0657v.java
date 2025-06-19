package androidx.compose.material3.internal;

import androidx.compose.animation.d0;

/* renamed from: androidx.compose.material3.internal.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0657v {
    public final int a;
    public final int b;
    public final int c;
    public final int d;
    public final long e;

    public C0657v(int i, long j, int i2, int i3, int i4) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
        this.e = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0657v)) {
            return false;
        }
        C0657v c0657v = (C0657v) obj;
        return this.a == c0657v.a && this.b == c0657v.b && this.c == c0657v.c && this.d == c0657v.d && this.e == c0657v.e;
    }

    public final int hashCode() {
        return Long.hashCode(this.e) + d0.b(this.d, d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CalendarMonth(year=");
        sb.append(this.a);
        sb.append(", month=");
        sb.append(this.b);
        sb.append(", numberOfDays=");
        sb.append(this.c);
        sb.append(", daysFromStartOfWeekToFirstOfMonth=");
        sb.append(this.d);
        sb.append(", startUtcTimeMillis=");
        return d0.q(sb, this.e, ')');
    }
}
