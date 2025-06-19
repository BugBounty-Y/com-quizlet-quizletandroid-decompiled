package assistantMode.types.unions;

import assistantMode.enums.F;
import assistantMode.enums.G;
import assistantMode.refactored.enums.g;
import assistantMode.refactored.enums.h;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class VideoAttribute$$serializer implements D {

    @NotNull
    public static final VideoAttribute$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        VideoAttribute$$serializer videoAttribute$$serializer = new VideoAttribute$$serializer();
        INSTANCE = videoAttribute$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("VideoAttribute", videoAttribute$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("providerVideoId", false);
        pluginGeneratedSerialDescriptor.k("provider", false);
        pluginGeneratedSerialDescriptor.k("clipStartSeconds", false);
        pluginGeneratedSerialDescriptor.k("clipEndSeconds", false);
        pluginGeneratedSerialDescriptor.k("mediaType", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private VideoAttribute$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        K k = K.a;
        return new KSerializer[]{q0.a, F.f, k, k, g.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public VideoAttribute deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        int iN = 0;
        int iN2 = 0;
        String strR = null;
        G g = null;
        h hVar = null;
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
            } else if (iT == 3) {
                iN2 = aVarC.n(descriptor2, 3);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                hVar = (h) aVarC.z(descriptor2, 4, g.f, hVar);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new VideoAttribute(i, strR, g, iN, iN2, hVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull VideoAttribute value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.a);
        bVarC.i(descriptor2, 1, F.f, value.b);
        bVarC.l(2, value.c, descriptor2);
        bVarC.l(3, value.d, descriptor2);
        boolean zD = bVarC.D(descriptor2);
        h hVar = value.e;
        if (zD || hVar != h.d) {
            bVarC.i(descriptor2, 4, g.f, hVar);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
