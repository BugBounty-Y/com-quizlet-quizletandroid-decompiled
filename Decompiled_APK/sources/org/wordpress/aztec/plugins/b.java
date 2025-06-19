package org.wordpress.aztec.plugins;

import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_camera.G2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends G2 {
    public final Intent a;

    public b(Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        this.a = intent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "PastedIntent(intent=" + this.a + ')';
    }
}
