package org.wordpress.aztec.plugins;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_camera.G2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends G2 {
    public final String a;

    public a(String text) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return d0.r(new StringBuilder("HtmlText(text="), this.a, ')');
    }
}
