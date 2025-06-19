package androidx.core.app;

import android.app.PendingIntent;
import android.os.Bundle;
import androidx.core.graphics.drawable.IconCompat;

/* renamed from: androidx.core.app.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1029p {
    public final Bundle a;
    public IconCompat b;
    public final T[] c;
    public final boolean d;
    public final boolean e;
    public final int f;
    public final CharSequence g;
    public final PendingIntent h;

    public C1029p(IconCompat iconCompat, CharSequence charSequence, PendingIntent pendingIntent, Bundle bundle, T[] tArr, T[] tArr2) {
        this.e = true;
        this.b = iconCompat;
        if (iconCompat != null && iconCompat.c() == 2) {
            this.f = iconCompat.b();
        }
        this.g = C1034v.b(charSequence);
        this.h = pendingIntent;
        this.a = bundle;
        this.c = tArr;
        this.d = true;
        this.e = true;
    }

    public final IconCompat a() {
        int i;
        if (this.b == null && (i = this.f) != 0) {
            this.b = IconCompat.a(null, "", i);
        }
        return this.b;
    }
}
