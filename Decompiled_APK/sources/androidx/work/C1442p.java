package androidx.work;

import android.app.Notification;

/* renamed from: androidx.work.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1442p {
    public final int a;
    public final int b;
    public final Notification c;

    public C1442p(int i, Notification notification, int i2) {
        this.a = i;
        this.c = notification;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C1442p.class != obj.getClass()) {
            return false;
        }
        C1442p c1442p = (C1442p) obj;
        if (this.a == c1442p.a && this.b == c1442p.b) {
            return this.c.equals(c1442p.c);
        }
        return false;
    }

    public final int hashCode() {
        return this.c.hashCode() + (((this.a * 31) + this.b) * 31);
    }

    public final String toString() {
        return "ForegroundInfo{mNotificationId=" + this.a + ", mForegroundServiceType=" + this.b + ", mNotification=" + this.c + '}';
    }
}
