package assistantMode.refactored.types;

import assistantMode.types.aliases.ExperimentConfiguration;
import assistantMode.types.aliases.ExperimentConfiguration$$serializer;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class StudyEngineSettings$$serializer implements D {

    @NotNull
    public static final StudyEngineSettings$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        StudyEngineSettings$$serializer studyEngineSettings$$serializer = new StudyEngineSettings$$serializer();
        INSTANCE = studyEngineSettings$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.StudyEngineSettings", studyEngineSettings$$serializer, 6);
        pluginGeneratedSerialDescriptor.k("studySettings", false);
        pluginGeneratedSerialDescriptor.k("gradingSettings", false);
        pluginGeneratedSerialDescriptor.k("studyLearnSettings", false);
        pluginGeneratedSerialDescriptor.k("experimentConfiguration", false);
        pluginGeneratedSerialDescriptor.k("studyMode", false);
        pluginGeneratedSerialDescriptor.k("shouldFetchStudiableMetadata", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private StudyEngineSettings$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{StudySettings$$serializer.INSTANCE, AssistantGradingSettings$$serializer.INSTANCE, R1.e(StudyLearnSettings$$serializer.INSTANCE), R1.e(ExperimentConfiguration$$serializer.INSTANCE), assistantMode.refactored.e.f, C5053g.a};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public StudyEngineSettings deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        boolean zQ = false;
        StudySettings studySettings = null;
        AssistantGradingSettings assistantGradingSettings = null;
        StudyLearnSettings studyLearnSettings = null;
        ExperimentConfiguration experimentConfiguration = null;
        assistantMode.refactored.f fVar = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    studySettings = (StudySettings) aVarC.z(descriptor2, 0, StudySettings$$serializer.INSTANCE, studySettings);
                    i |= 1;
                    break;
                case 1:
                    assistantGradingSettings = (AssistantGradingSettings) aVarC.z(descriptor2, 1, AssistantGradingSettings$$serializer.INSTANCE, assistantGradingSettings);
                    i |= 2;
                    break;
                case 2:
                    studyLearnSettings = (StudyLearnSettings) aVarC.v(descriptor2, 2, StudyLearnSettings$$serializer.INSTANCE, studyLearnSettings);
                    i |= 4;
                    break;
                case 3:
                    experimentConfiguration = (ExperimentConfiguration) aVarC.v(descriptor2, 3, ExperimentConfiguration$$serializer.INSTANCE, experimentConfiguration);
                    i |= 8;
                    break;
                case 4:
                    fVar = (assistantMode.refactored.f) aVarC.z(descriptor2, 4, assistantMode.refactored.e.f, fVar);
                    i |= 16;
                    break;
                case 5:
                    zQ = aVarC.q(descriptor2, 5);
                    i |= 32;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new StudyEngineSettings(i, studySettings, assistantGradingSettings, studyLearnSettings, experimentConfiguration, fVar, zQ);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull StudyEngineSettings value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, StudySettings$$serializer.INSTANCE, value.a);
        bVarC.i(descriptor2, 1, AssistantGradingSettings$$serializer.INSTANCE, value.b);
        bVarC.s(descriptor2, 2, StudyLearnSettings$$serializer.INSTANCE, value.c);
        bVarC.s(descriptor2, 3, ExperimentConfiguration$$serializer.INSTANCE, value.d);
        bVarC.i(descriptor2, 4, assistantMode.refactored.e.f, value.e);
        bVarC.p(descriptor2, 5, value.f);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
