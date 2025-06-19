package assistantMode.grading;

import com.google.android.gms.internal.mlkit_vision_camera.J2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g extends J2 {
    public final grading.core.d a;

    public g(grading.core.d writtenGraderSettings) {
        Intrinsics.checkNotNullParameter(writtenGraderSettings, "writtenGraderSettings");
        this.a = writtenGraderSettings;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && Intrinsics.b(this.a, ((g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Written(writtenGraderSettings=" + this.a + ")";
    }
}
