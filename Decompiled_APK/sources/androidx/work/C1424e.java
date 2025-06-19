package androidx.work;

import android.net.Uri;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.work.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1424e {
    public final Uri a;
    public final boolean b;

    public C1424e(boolean z, Uri uri) {
        Intrinsics.checkNotNullParameter(uri, "uri");
        this.a = uri;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!C1424e.class.equals(obj != null ? obj.getClass() : null)) {
            return false;
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type androidx.work.Constraints.ContentUriTrigger");
        C1424e c1424e = (C1424e) obj;
        return Intrinsics.b(this.a, c1424e.a) && this.b == c1424e.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }
}
