package androidx.compose.material3.internal;

import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.TextStyle;
import java.time.temporal.WeekFields;
import java.util.ArrayList;
import java.util.Locale;
import kotlin.Pair;

/* renamed from: androidx.compose.material3.internal.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0656u extends AbstractC0655t {
    public static final ZoneId d = ZoneId.of("UTC");
    public final int b;
    public final ArrayList c;

    public C0656u(Locale locale) {
        this.b = WeekFields.of(locale).getFirstDayOfWeek().getValue();
        DayOfWeek[] dayOfWeekArrValues = DayOfWeek.values();
        ArrayList arrayList = new ArrayList(dayOfWeekArrValues.length);
        for (DayOfWeek dayOfWeek : dayOfWeekArrValues) {
            arrayList.add(new Pair(dayOfWeek.getDisplayName(TextStyle.FULL, locale), dayOfWeek.getDisplayName(TextStyle.NARROW, locale)));
        }
        this.c = arrayList;
    }

    @Override // androidx.compose.material3.internal.AbstractC0655t
    public final C0657v a(long j) {
        return d(Instant.ofEpochMilli(j).atZone(d).withDayOfMonth(1).toLocalDate());
    }

    @Override // androidx.compose.material3.internal.AbstractC0655t
    public final C0654s b() {
        LocalDate localDateNow = LocalDate.now();
        return new C0654s(localDateNow.atTime(LocalTime.MIDNIGHT).atZone(d).toInstant().toEpochMilli(), localDateNow.getYear(), localDateNow.getMonthValue(), localDateNow.getDayOfMonth());
    }

    public final C0654s c(long j) {
        LocalDate localDate = Instant.ofEpochMilli(j).atZone(d).toLocalDate();
        return new C0654s(1000 * localDate.atStartOfDay().toEpochSecond(ZoneOffset.UTC), localDate.getYear(), localDate.getMonthValue(), localDate.getDayOfMonth());
    }

    public final C0657v d(LocalDate localDate) {
        int value = localDate.getDayOfWeek().getValue() - this.b;
        if (value < 0) {
            value += 7;
        }
        int i = value;
        return new C0657v(localDate.getYear(), localDate.atTime(LocalTime.MIDNIGHT).atZone(d).toInstant().toEpochMilli(), localDate.getMonthValue(), localDate.lengthOfMonth(), i);
    }

    public final String toString() {
        return "CalendarModel";
    }
}
