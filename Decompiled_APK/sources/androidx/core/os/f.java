package androidx.core.os;

import android.os.LocaleList;
import java.util.Locale;

/* loaded from: classes.dex */
public final class f {
    public static final f b = new f(new g(new LocaleList(new Locale[0])));
    public final g a;

    public f(g gVar) {
        this.a = gVar;
    }

    public static f a(String str) {
        if (str == null || str.isEmpty()) {
            return b;
        }
        String[] strArrSplit = str.split(",", -1);
        int length = strArrSplit.length;
        Locale[] localeArr = new Locale[length];
        for (int i = 0; i < length; i++) {
            String str2 = strArrSplit[i];
            int i2 = e.a;
            localeArr[i] = Locale.forLanguageTag(str2);
        }
        return new f(new g(new LocaleList(localeArr)));
    }

    public final Locale b(int i) {
        return this.a.a.get(i);
    }

    public final int c() {
        return this.a.a.size();
    }

    public final boolean equals(Object obj) {
        if (obj instanceof f) {
            return this.a.equals(((f) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.a.hashCode();
    }

    public final String toString() {
        return this.a.a.toString();
    }
}
