package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class O extends A {
    public final String a;
    public final boolean b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final boolean g;

    public O(String name, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = name;
        this.b = z;
        this.c = z2;
        this.d = z3;
        this.e = z4;
        this.f = z5;
        this.g = z6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof O)) {
            return false;
        }
        O o = (O) obj;
        return Intrinsics.b(this.a, o.a) && this.b == o.b && this.c == o.c && this.d == o.d && this.e == o.e && this.f == o.f && this.g == o.g;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.g) + androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DayItem(name=");
        sb.append(this.a);
        sb.append(", isFirstDayOfWeek=");
        sb.append(this.b);
        sb.append(", isLastDayOfWeek=");
        sb.append(this.c);
        sb.append(", isCurrentDay=");
        sb.append(this.d);
        sb.append(", isCurrentMonth=");
        sb.append(this.e);
        sb.append(", isDayStreak=");
        sb.append(this.f);
        sb.append(", isWeekStreak=");
        return android.support.v4.media.session.a.o(")", sb, this.g);
    }
}
