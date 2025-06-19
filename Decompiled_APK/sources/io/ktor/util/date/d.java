package io.ktor.util.date;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
/* loaded from: classes3.dex */
public final class d implements Comparable<d> {

    @NotNull
    public static final c Companion = new c();
    public static final KSerializer[] j = {null, null, null, AbstractC5047c0.e("io.ktor.util.date.WeekDay", f.values()), null, null, AbstractC5047c0.e("io.ktor.util.date.Month", e.values()), null, null};
    public final int a;
    public final int b;
    public final int c;
    public final f d;
    public final int e;
    public final int f;
    public final e g;
    public final int h;
    public final long i;

    static {
        a.a(0L);
    }

    public /* synthetic */ d(int i, int i2, int i3, int i4, f fVar, int i5, int i6, e eVar, int i7, long j2) {
        if (511 != (i & 511)) {
            AbstractC5047c0.k(i, 511, b.a.getDescriptor());
            throw null;
        }
        this.a = i2;
        this.b = i3;
        this.c = i4;
        this.d = fVar;
        this.e = i5;
        this.f = i6;
        this.g = eVar;
        this.h = i7;
        this.i = j2;
    }

    @Override // java.lang.Comparable
    public final int compareTo(d dVar) {
        d other = dVar;
        Intrinsics.checkNotNullParameter(other, "other");
        return Intrinsics.h(this.i, other.i);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && this.b == dVar.b && this.c == dVar.c && this.d == dVar.d && this.e == dVar.e && this.f == dVar.f && this.g == dVar.g && this.h == dVar.h && this.i == dVar.i;
    }

    public final int hashCode() {
        return Long.hashCode(this.i) + d0.b(this.h, (this.g.hashCode() + d0.b(this.f, d0.b(this.e, (this.d.hashCode() + d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31)) * 31, 31), 31)) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GMTDate(seconds=");
        sb.append(this.a);
        sb.append(", minutes=");
        sb.append(this.b);
        sb.append(", hours=");
        sb.append(this.c);
        sb.append(", dayOfWeek=");
        sb.append(this.d);
        sb.append(", dayOfMonth=");
        sb.append(this.e);
        sb.append(", dayOfYear=");
        sb.append(this.f);
        sb.append(", month=");
        sb.append(this.g);
        sb.append(", year=");
        sb.append(this.h);
        sb.append(", timestamp=");
        return d0.q(sb, this.i, ')');
    }

    public d(int i, int i2, int i3, f dayOfWeek, int i4, int i5, e month, int i6, long j2) {
        Intrinsics.checkNotNullParameter(dayOfWeek, "dayOfWeek");
        Intrinsics.checkNotNullParameter(month, "month");
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = dayOfWeek;
        this.e = i4;
        this.f = i5;
        this.g = month;
        this.h = i6;
        this.i = j2;
    }
}
