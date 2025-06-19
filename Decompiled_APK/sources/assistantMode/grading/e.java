package assistantMode.grading;

import com.google.android.gms.internal.mlkit_vision_camera.J2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e extends J2 {
    public final grading.core.d a;

    public e(grading.core.d multipleChoiceGraderSettings) {
        Intrinsics.checkNotNullParameter(multipleChoiceGraderSettings, "multipleChoiceGraderSettings");
        this.a = multipleChoiceGraderSettings;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof e) && Intrinsics.b(this.a, ((e) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "MultipleChoice(multipleChoiceGraderSettings=" + this.a + ")";
    }
}
