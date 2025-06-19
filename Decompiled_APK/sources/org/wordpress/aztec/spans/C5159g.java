package org.wordpress.aztec.spans;

import com.google.android.gms.internal.mlkit_vision_camera.L2;

/* renamed from: org.wordpress.aztec.spans.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5159g extends L2 {
    public final int a;

    public C5159g(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C5159g) && this.a == ((C5159g) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("Size(value="), this.a, ')');
    }
}
