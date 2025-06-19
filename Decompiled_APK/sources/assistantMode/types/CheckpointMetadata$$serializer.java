package assistantMode.types;

import assistantMode.types.CheckpointMetadata;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import java.util.Map;
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
public final class CheckpointMetadata$$serializer implements kotlinx.serialization.internal.D {

    @NotNull
    public static final CheckpointMetadata$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        CheckpointMetadata$$serializer checkpointMetadata$$serializer = new CheckpointMetadata$$serializer();
        INSTANCE = checkpointMetadata$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("CheckpointMetadata", checkpointMetadata$$serializer, 1);
        pluginGeneratedSerialDescriptor.k("meteringData", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private CheckpointMetadata$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{R1.e(CheckpointMetadata.b[0])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public CheckpointMetadata deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = CheckpointMetadata.b;
        boolean z = true;
        boolean z2 = false;
        Map map = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else {
                if (iT != 0) {
                    throw new UnknownFieldException(iT);
                }
                map = (Map) aVarC.v(descriptor2, 0, kSerializerArr[0], map);
                z2 = true;
            }
        }
        aVarC.b(descriptor2);
        CheckpointMetadata checkpointMetadata = new CheckpointMetadata();
        if (z2) {
            checkpointMetadata.a = map;
            return checkpointMetadata;
        }
        checkpointMetadata.a = null;
        return checkpointMetadata;
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull CheckpointMetadata value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        CheckpointMetadata.Companion companion = CheckpointMetadata.Companion;
        if (bVarC.D(descriptor2) || value.a != null) {
            bVarC.s(descriptor2, 0, CheckpointMetadata.b[0], value.a);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
