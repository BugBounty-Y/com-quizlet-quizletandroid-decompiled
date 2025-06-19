package assistantMode.types;

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
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class FlashcardsStepMetadata$$serializer implements kotlinx.serialization.internal.D {

    @NotNull
    public static final FlashcardsStepMetadata$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FlashcardsStepMetadata$$serializer flashcardsStepMetadata$$serializer = new FlashcardsStepMetadata$$serializer();
        INSTANCE = flashcardsStepMetadata$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FlashcardsStepMetadata", flashcardsStepMetadata$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("isSortingEnabled", false);
        pluginGeneratedSerialDescriptor.k("meteringData", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FlashcardsStepMetadata$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{C5053g.a, R1.e(FlashcardsStepMetadata.c[1])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FlashcardsStepMetadata deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = FlashcardsStepMetadata.c;
        Map map = null;
        boolean z = true;
        int i = 0;
        boolean zQ = false;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                zQ = aVarC.q(descriptor2, 0);
                i |= 1;
            } else {
                if (iT != 1) {
                    throw new UnknownFieldException(iT);
                }
                map = (Map) aVarC.v(descriptor2, 1, kSerializerArr[1], map);
                i |= 2;
            }
        }
        aVarC.b(descriptor2);
        return new FlashcardsStepMetadata(i, zQ, map);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FlashcardsStepMetadata value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.p(descriptor2, 0, value.a);
        if (bVarC.D(descriptor2) || value.b != null) {
            bVarC.s(descriptor2, 1, FlashcardsStepMetadata.c[1], value.b);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
