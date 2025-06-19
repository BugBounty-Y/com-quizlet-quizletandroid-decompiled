package assistantMode.types.unions;

import assistantMode.refactored.enums.g;
import assistantMode.refactored.enums.h;
import com.amazon.device.ads.DTBMetricsConfiguration;
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
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class AudioAttribute$$serializer implements D {

    @NotNull
    public static final AudioAttribute$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        AudioAttribute$$serializer audioAttribute$$serializer = new AudioAttribute$$serializer();
        INSTANCE = audioAttribute$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("AudioAttribute", audioAttribute$$serializer, 3);
        pluginGeneratedSerialDescriptor.k(DTBMetricsConfiguration.APSMETRICS_URL, false);
        pluginGeneratedSerialDescriptor.k("slowUrl", false);
        pluginGeneratedSerialDescriptor.k("mediaType", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private AudioAttribute$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        return new KSerializer[]{q0Var, q0Var, g.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public AudioAttribute deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        String strR = null;
        boolean z = true;
        int i = 0;
        String strR2 = null;
        h hVar = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                strR = aVarC.r(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                strR2 = aVarC.r(descriptor2, 1);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                hVar = (h) aVarC.z(descriptor2, 2, g.f, hVar);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new AudioAttribute(i, strR, strR2, hVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull AudioAttribute value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.a);
        bVarC.r(descriptor2, 1, value.b);
        boolean zD = bVarC.D(descriptor2);
        h hVar = value.c;
        if (zD || hVar != h.e) {
            bVarC.i(descriptor2, 2, g.f, hVar);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
