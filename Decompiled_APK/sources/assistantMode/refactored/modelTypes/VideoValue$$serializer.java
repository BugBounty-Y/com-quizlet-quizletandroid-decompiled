package assistantMode.refactored.modelTypes;

import assistantMode.enums.F;
import assistantMode.enums.G;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class VideoValue$$serializer implements D {

    @NotNull
    public static final VideoValue$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        VideoValue$$serializer videoValue$$serializer = new VideoValue$$serializer();
        INSTANCE = videoValue$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("3", videoValue$$serializer, 4);
        pluginGeneratedSerialDescriptor.k("providerVideoId", false);
        pluginGeneratedSerialDescriptor.k("provider", false);
        pluginGeneratedSerialDescriptor.k("clipStartSeconds", false);
        pluginGeneratedSerialDescriptor.k("clipEndSeconds", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private VideoValue$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        K k = K.a;
        return new KSerializer[]{q0.a, F.f, k, k};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public VideoValue deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        int iN = 0;
        int iN2 = 0;
        String strR = null;
        G g = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                strR = aVarC.r(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                g = (G) aVarC.z(descriptor2, 1, F.f, g);
                i |= 2;
            } else if (iT == 2) {
                iN = aVarC.n(descriptor2, 2);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                iN2 = aVarC.n(descriptor2, 3);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new VideoValue(i, strR, g, iN, iN2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull VideoValue value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.a);
        bVarC.i(descriptor2, 1, F.f, value.b);
        bVarC.l(2, value.c, descriptor2);
        bVarC.l(3, value.d, descriptor2);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
