package okhttp3;

import androidx.compose.animation.d0;
import java.text.DateFormat;
import java.util.Date;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: okhttp3.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5083l {
    public static final Pattern j = Pattern.compile("(\\d{2,4})[^\\d]*");
    public static final Pattern k = Pattern.compile("(?i)(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec).*");
    public static final Pattern l = Pattern.compile("(\\d{1,2})[^\\d]*");
    public static final Pattern m = Pattern.compile("(\\d{1,2}):(\\d{1,2}):(\\d{1,2})[^\\d]*");
    public final String a;
    public final String b;
    public final long c;
    public final String d;
    public final String e;
    public final boolean f;
    public final boolean g;
    public final boolean h;
    public final boolean i;

    public C5083l(String str, String str2, long j2, String str3, String str4, boolean z, boolean z2, boolean z3, boolean z4) {
        this.a = str;
        this.b = str2;
        this.c = j2;
        this.d = str3;
        this.e = str4;
        this.f = z;
        this.g = z2;
        this.h = z3;
        this.i = z4;
    }

    public final String a(boolean z) {
        StringBuilder sb = new StringBuilder();
        sb.append(this.a);
        sb.append('=');
        sb.append(this.b);
        if (this.h) {
            long j2 = this.c;
            if (j2 == Long.MIN_VALUE) {
                sb.append("; max-age=0");
            } else {
                sb.append("; expires=");
                Date date = new Date(j2);
                androidx.camera.core.impl.utils.executor.b bVar = okhttp3.internal.http.c.a;
                Intrinsics.checkNotNullParameter(date, "<this>");
                String str = ((DateFormat) okhttp3.internal.http.c.a.get()).format(date);
                Intrinsics.checkNotNullExpressionValue(str, "STANDARD_DATE_FORMAT.get().format(this)");
                sb.append(str);
            }
        }
        if (!this.i) {
            sb.append("; domain=");
            if (z) {
                sb.append(".");
            }
            sb.append(this.d);
        }
        sb.append("; path=");
        sb.append(this.e);
        if (this.f) {
            sb.append("; secure");
        }
        if (this.g) {
            sb.append("; httponly");
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString()");
        return string;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C5083l)) {
            return false;
        }
        C5083l c5083l = (C5083l) obj;
        return Intrinsics.b(c5083l.a, this.a) && Intrinsics.b(c5083l.b, this.b) && c5083l.c == this.c && Intrinsics.b(c5083l.d, this.d) && Intrinsics.b(c5083l.e, this.e) && c5083l.f == this.f && c5083l.g == this.g && c5083l.h == this.h && c5083l.i == this.i;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.i) + d0.g(d0.g(d0.g(d0.e(d0.e(d0.d(d0.e(d0.e(527, 31, this.a), 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h);
    }

    public final String toString() {
        return a(false);
    }
}
