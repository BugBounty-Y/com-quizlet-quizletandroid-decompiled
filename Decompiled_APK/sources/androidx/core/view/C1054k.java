package androidx.core.view;

import android.view.DisplayCutout;
import java.util.Objects;

/* renamed from: androidx.core.view.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1054k {
    public final DisplayCutout a;

    public C1054k(DisplayCutout displayCutout) {
        this.a = displayCutout;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C1054k.class != obj.getClass()) {
            return false;
        }
        return Objects.equals(this.a, ((C1054k) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "DisplayCutoutCompat{" + this.a + "}";
    }
}
