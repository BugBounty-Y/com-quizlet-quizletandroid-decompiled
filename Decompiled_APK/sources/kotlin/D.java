package kotlin;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3320b;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class D implements Comparable {

    @NotNull
    public static final C b = new C(null);
    public final long a;

    public /* synthetic */ D(long j) {
        this.a = j;
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        return Intrinsics.h(this.a ^ Long.MIN_VALUE, ((D) obj).a ^ Long.MIN_VALUE);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof D) {
            return this.a == ((D) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return AbstractC3320b.d(10, this.a);
    }
}
