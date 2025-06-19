package com.quizlet.qutils.string;

import android.content.Context;
import android.icu.text.DateFormat;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.Date;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements g {
    public final String a;
    public final Date b;

    public b(String datePattern, Date date) {
        Intrinsics.checkNotNullParameter(datePattern, "datePattern");
        Intrinsics.checkNotNullParameter(date, "date");
        this.a = datePattern;
        this.b = date;
    }

    @Override // com.quizlet.qutils.string.g
    public final String a(Context context) {
        return AbstractC3053s1.e(this, context);
    }

    @Override // com.quizlet.qutils.string.g
    public final String b(InterfaceC0806l interfaceC0806l) {
        return AbstractC3053s1.g(this, interfaceC0806l);
    }

    @Override // com.quizlet.qutils.string.g
    public final CharSequence c(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Locale locale = context.getResources().getConfiguration().getLocales().get(0);
        if (locale == null) {
            locale = Locale.getDefault(Locale.Category.FORMAT);
            Intrinsics.checkNotNullExpressionValue(locale, "getDefault(...)");
        }
        String str = DateFormat.getPatternInstance(this.a, locale).format(this.b);
        Intrinsics.checkNotNullExpressionValue(str, "format(...)");
        return str;
    }

    @Override // com.quizlet.qutils.string.g
    public final CharSequence d(InterfaceC0806l interfaceC0806l, int i) {
        return AbstractC3053s1.b(this, interfaceC0806l);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "DateFormattedStringData(datePattern=" + this.a + ", date=" + this.b + ")";
    }
}
