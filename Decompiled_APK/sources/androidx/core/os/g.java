package androidx.core.os;

import android.os.LocaleList;

/* loaded from: classes.dex */
public final class g {
    public final LocaleList a;

    public g(LocaleList localeList) {
        this.a = localeList;
    }

    public final boolean equals(Object obj) {
        return this.a.equals(((g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return this.a.toString();
    }
}
