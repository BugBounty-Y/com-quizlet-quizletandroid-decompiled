package assistantMode.refactored.types;

import assistantMode.types.aliases.ExperimentConfiguration;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class StudyEngineSettings {

    @NotNull
    public static final Companion Companion = new Companion();
    public final StudySettings a;
    public final AssistantGradingSettings b;
    public final StudyLearnSettings c;
    public final ExperimentConfiguration d;
    public final assistantMode.refactored.f e;
    public final boolean f;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudyEngineSettings$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudyEngineSettings(int i, StudySettings studySettings, AssistantGradingSettings assistantGradingSettings, StudyLearnSettings studyLearnSettings, ExperimentConfiguration experimentConfiguration, assistantMode.refactored.f fVar, boolean z) {
        if (63 != (i & 63)) {
            AbstractC5047c0.k(i, 63, StudyEngineSettings$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = studySettings;
        this.b = assistantGradingSettings;
        this.c = studyLearnSettings;
        this.d = experimentConfiguration;
        this.e = fVar;
        this.f = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyEngineSettings)) {
            return false;
        }
        StudyEngineSettings studyEngineSettings = (StudyEngineSettings) obj;
        return Intrinsics.b(this.a, studyEngineSettings.a) && Intrinsics.b(this.b, studyEngineSettings.b) && Intrinsics.b(this.c, studyEngineSettings.c) && Intrinsics.b(this.d, studyEngineSettings.d) && this.e == studyEngineSettings.e && this.f == studyEngineSettings.f;
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        StudyLearnSettings studyLearnSettings = this.c;
        int iHashCode2 = (iHashCode + (studyLearnSettings == null ? 0 : studyLearnSettings.hashCode())) * 31;
        ExperimentConfiguration experimentConfiguration = this.d;
        return Boolean.hashCode(this.f) + ((this.e.hashCode() + ((iHashCode2 + (experimentConfiguration != null ? experimentConfiguration.hashCode() : 0)) * 31)) * 31);
    }

    public final String toString() {
        return "StudyEngineSettings(studySettings=" + this.a + ", gradingSettings=" + this.b + ", studyLearnSettings=" + this.c + ", experimentConfiguration=" + this.d + ", studyMode=" + this.e + ", shouldFetchStudiableMetadata=" + this.f + ")";
    }
}
