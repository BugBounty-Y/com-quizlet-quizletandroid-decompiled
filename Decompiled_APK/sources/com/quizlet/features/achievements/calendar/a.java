package com.quizlet.features.achievements.calendar;

import java.time.LocalDate;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final LocalDate a;
    public final Locale b;

    public a() {
        LocalDate date = LocalDate.now();
        Locale locale = Locale.getDefault();
        Intrinsics.checkNotNullParameter(date, "date");
        Intrinsics.checkNotNullParameter(locale, "locale");
        this.a = date;
        this.b = locale;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "StreakLocalDate(date=" + this.a + ", locale=" + this.b + ")";
    }
}
