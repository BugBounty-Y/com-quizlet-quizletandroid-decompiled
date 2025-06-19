package androidx.glance.session;

import androidx.camera.camera2.internal.s0;
import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3397u1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class I {
    public final long a;
    public final long b;
    public final long c;
    public final s0 d;

    public I() {
        kotlin.time.a aVar = kotlin.time.b.b;
        kotlin.time.d dVar = kotlin.time.d.d;
        long jF = AbstractC3397u1.f(45, dVar);
        long jF2 = AbstractC3397u1.f(5, dVar);
        long jF3 = AbstractC3397u1.f(5, dVar);
        s0 s0Var = H.a;
        this.a = jF;
        this.b = jF2;
        this.c = jF3;
        this.d = s0Var;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof I)) {
            return false;
        }
        I i = (I) obj;
        return kotlin.time.b.d(this.a, i.a) && kotlin.time.b.d(this.b, i.b) && kotlin.time.b.d(this.c, i.c) && Intrinsics.b(this.d, i.d);
    }

    public final int hashCode() {
        kotlin.time.a aVar = kotlin.time.b.b;
        return this.d.hashCode() + d0.d(d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        return "TimeoutOptions(initialTimeout=" + ((Object) kotlin.time.b.j(this.a)) + ", additionalTime=" + ((Object) kotlin.time.b.j(this.b)) + ", idleTimeout=" + ((Object) kotlin.time.b.j(this.c)) + ", timeSource=" + this.d + ')';
    }
}
