package assistantMode.types.aliases;

import assistantMode.experiments.c;
import assistantMode.experiments.d;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.encoding.a;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class ExperimentConfiguration$$serializer implements D {

    @NotNull
    public static final ExperimentConfiguration$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        ExperimentConfiguration$$serializer experimentConfiguration$$serializer = new ExperimentConfiguration$$serializer();
        INSTANCE = experimentConfiguration$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.types.aliases.ExperimentConfiguration", experimentConfiguration$$serializer, 1);
        pluginGeneratedSerialDescriptor.k("granular_study_direction", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private ExperimentConfiguration$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{R1.e(c.f)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public ExperimentConfiguration deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        d dVar = null;
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
                dVar = (d) aVarC.v(descriptor2, 0, c.f, dVar);
                i = 1;
            }
        }
        aVarC.b(descriptor2);
        return new ExperimentConfiguration(i, dVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull ExperimentConfiguration value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        if (bVarC.D(descriptor2) || value.a != null) {
            bVarC.s(descriptor2, 0, c.f, value.a);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
