package androidx.core.app;

import android.os.Bundle;
import java.util.Objects;

/* loaded from: classes.dex */
public final class Q {
    public CharSequence a;
    public String b;
    public String c;
    public boolean d;
    public boolean e;

    public final Bundle a() {
        Bundle bundle = new Bundle();
        bundle.putCharSequence("name", this.a);
        bundle.putBundle("icon", null);
        bundle.putString("uri", this.b);
        bundle.putString("key", this.c);
        bundle.putBoolean("isBot", this.d);
        bundle.putBoolean("isImportant", this.e);
        return bundle;
    }

    public final boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Q)) {
            return false;
        }
        Q q = (Q) obj;
        String str = this.c;
        String str2 = q.c;
        return (str == null && str2 == null) ? Objects.equals(Objects.toString(this.a), Objects.toString(q.a)) && Objects.equals(this.b, q.b) && Boolean.valueOf(this.d).equals(Boolean.valueOf(q.d)) && Boolean.valueOf(this.e).equals(Boolean.valueOf(q.e)) : Objects.equals(str, str2);
    }

    public final int hashCode() {
        String str = this.c;
        if (str != null) {
            return str.hashCode();
        }
        return Objects.hash(this.a, this.b, Boolean.valueOf(this.d), Boolean.valueOf(this.e));
    }
}
