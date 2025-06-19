package androidx.compose.material3;

import androidx.compose.material3.internal.AbstractC0646j;
import java.util.LinkedHashMap;
import java.util.Locale;

/* renamed from: androidx.compose.material3.s0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0716s0 {
    public final LinkedHashMap a = new LinkedHashMap();

    public final String a(Long l, Locale locale, boolean z) {
        if (l == null) {
            return null;
        }
        return AbstractC0646j.f(l.longValue(), z ? "yMMMMEEEEd" : "yMMMd", locale, this.a);
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C0716s0)) {
            return false;
        }
        ((C0716s0) obj).getClass();
        return true;
    }

    public final int hashCode() {
        return 436998964;
    }
}
