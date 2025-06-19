package assistantMode.types;

import assistantMode.enums.C1447a;
import assistantMode.enums.EnumC1448b;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class RevealSelfAssessmentAnswer$$serializer implements kotlinx.serialization.internal.D {

    @NotNull
    public static final RevealSelfAssessmentAnswer$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RevealSelfAssessmentAnswer$$serializer revealSelfAssessmentAnswer$$serializer = new RevealSelfAssessmentAnswer$$serializer();
        INSTANCE = revealSelfAssessmentAnswer$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("RevealSelfAssessmentAnswer", revealSelfAssessmentAnswer$$serializer, 1);
        pluginGeneratedSerialDescriptor.k("value", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RevealSelfAssessmentAnswer$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{C1447a.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RevealSelfAssessmentAnswer deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        EnumC1448b enumC1448b = null;
        boolean z = true;
        int i = 0;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else {
                if (iT != 0) {
                    throw new UnknownFieldException(iT);
                }
                enumC1448b = (EnumC1448b) aVarC.z(descriptor2, 0, C1447a.f, enumC1448b);
                i = 1;
            }
        }
        aVarC.b(descriptor2);
        return new RevealSelfAssessmentAnswer(i, enumC1448b);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RevealSelfAssessmentAnswer value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, C1447a.f, value.a);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
