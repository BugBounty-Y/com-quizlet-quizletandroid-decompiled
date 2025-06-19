package io.reactivex.rxjava3.internal.util;

import java.io.Serializable;
import java.util.Objects;

/* loaded from: classes3.dex */
public final class d implements Serializable {
    public final Throwable a;

    public d(Throwable th) {
        this.a = th;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof d) {
            return Objects.equals(this.a, ((d) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "NotificationLite.Error[" + this.a + "]";
    }
}
