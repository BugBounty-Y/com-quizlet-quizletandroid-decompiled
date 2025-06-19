package org.wordpress.aztec.spans;

import com.google.android.gms.internal.mlkit_vision_camera.L2;

/* renamed from: org.wordpress.aztec.spans.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5158f extends L2 {
    public final float a;

    public C5158f(float f) {
        this.a = f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C5158f) && Float.compare(this.a, ((C5158f) obj).a) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.p(new StringBuilder("Scale(value="), this.a, ')');
    }
}
