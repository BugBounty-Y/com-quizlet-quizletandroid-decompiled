package org.wordpress.aztec.plugins;

import android.net.Uri;
import com.google.android.gms.internal.mlkit_vision_camera.G2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends G2 {
    public final Uri a;

    public c(Uri uri) {
        Intrinsics.checkNotNullParameter(uri, "uri");
        this.a = uri;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && Intrinsics.b(this.a, ((c) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Url(uri=" + this.a + ')';
    }
}
