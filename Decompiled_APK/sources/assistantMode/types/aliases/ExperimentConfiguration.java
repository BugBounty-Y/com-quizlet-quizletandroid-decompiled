package assistantMode.types.aliases;

import assistantMode.experiments.d;
import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class ExperimentConfiguration {

    @NotNull
    public static final Companion Companion = new Companion();
    public final d a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return ExperimentConfiguration$$serializer.INSTANCE;
        }
    }

    public ExperimentConfiguration() {
        this.a = null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ExperimentConfiguration) && this.a == ((ExperimentConfiguration) obj).a;
    }

    public final int hashCode() {
        d dVar = this.a;
        if (dVar == null) {
            return 0;
        }
        return dVar.hashCode();
    }

    public final String toString() {
        return "ExperimentConfiguration(granularStudyDirection=" + this.a + ")";
    }

    public /* synthetic */ ExperimentConfiguration(int i, d dVar) {
        if ((i & 1) == 0) {
            this.a = null;
        } else {
            this.a = dVar;
        }
    }
}
