package assistantMode.refactored.types;

import assistantMode.enums.C1449c;
import assistantMode.enums.EnumC1450d;
import assistantMode.refactored.types.Checkpoint;
import assistantMode.types.CheckpointMetadata;
import assistantMode.types.CheckpointMetadata$$serializer;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import java.util.List;
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
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class Checkpoint$$serializer implements D {

    @NotNull
    public static final Checkpoint$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        Checkpoint$$serializer checkpoint$$serializer = new Checkpoint$$serializer();
        INSTANCE = checkpoint$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("Checkpoint", checkpoint$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("progressState", false);
        pluginGeneratedSerialDescriptor.k("hasCompletedStudying", false);
        pluginGeneratedSerialDescriptor.k("roundResults", false);
        pluginGeneratedSerialDescriptor.k("checkpointNumber", false);
        pluginGeneratedSerialDescriptor.k("metadata", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private Checkpoint$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{C1449c.f, C5053g.a, R1.e(Checkpoint.f[2]), R1.e(K.a), CheckpointMetadata$$serializer.INSTANCE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public Checkpoint deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = Checkpoint.f;
        int i = 0;
        boolean zQ = false;
        EnumC1450d enumC1450d = null;
        List list = null;
        Integer num = null;
        CheckpointMetadata checkpointMetadata = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                enumC1450d = (EnumC1450d) aVarC.z(descriptor2, 0, C1449c.f, enumC1450d);
                i |= 1;
            } else if (iT == 1) {
                zQ = aVarC.q(descriptor2, 1);
                i |= 2;
            } else if (iT == 2) {
                list = (List) aVarC.v(descriptor2, 2, kSerializerArr[2], list);
                i |= 4;
            } else if (iT == 3) {
                num = (Integer) aVarC.v(descriptor2, 3, K.a, num);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                checkpointMetadata = (CheckpointMetadata) aVarC.z(descriptor2, 4, CheckpointMetadata$$serializer.INSTANCE, checkpointMetadata);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new Checkpoint(i, enumC1450d, zQ, list, num, checkpointMetadata);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull Checkpoint value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        Checkpoint.Companion companion = Checkpoint.Companion;
        bVarC.i(descriptor2, 0, C1449c.f, value.a);
        bVarC.p(descriptor2, 1, value.b);
        bVarC.s(descriptor2, 2, Checkpoint.f[2], value.c);
        bVarC.s(descriptor2, 3, K.a, value.d);
        boolean zD = bVarC.D(descriptor2);
        CheckpointMetadata checkpointMetadata = value.e;
        if (zD || !Intrinsics.b(checkpointMetadata, new CheckpointMetadata())) {
            bVarC.i(descriptor2, 4, CheckpointMetadata$$serializer.INSTANCE, checkpointMetadata);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
