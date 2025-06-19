package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class StudyLearnSettings {

    @NotNull
    public static final Companion Companion = new Companion();
    public final boolean a;
    public final boolean b;
    public final Long c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudyLearnSettings$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudyLearnSettings(int i, boolean z, boolean z2, Long l) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, StudyLearnSettings$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = z;
        this.b = z2;
        if ((i & 4) == 0) {
            this.c = null;
        } else {
            this.c = l;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyLearnSettings)) {
            return false;
        }
        StudyLearnSettings studyLearnSettings = (StudyLearnSettings) obj;
        return this.a == studyLearnSettings.a && this.b == studyLearnSettings.b && Intrinsics.b(this.c, studyLearnSettings.c);
    }

    public final int hashCode() {
        int iG = d0.g(Boolean.hashCode(this.a) * 31, 31, this.b);
        Long l = this.c;
        return iG + (l == null ? 0 : l.hashCode());
    }

    public final String toString() {
        return "StudyLearnSettings(showTasks=" + this.a + ", shouldInterleaveQuestions=" + this.b + ", crossModeResetTimestamp=" + this.c + ")";
    }
}
