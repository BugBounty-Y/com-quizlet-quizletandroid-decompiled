package assistantMode.types;

import assistantMode.types.PaywallMetadata;
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
public final class PaywallMetadata$$serializer implements kotlinx.serialization.internal.D {

    @NotNull
    public static final PaywallMetadata$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        PaywallMetadata$$serializer paywallMetadata$$serializer = new PaywallMetadata$$serializer();
        INSTANCE = paywallMetadata$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("PaywallMetadata", paywallMetadata$$serializer, 1);
        pluginGeneratedSerialDescriptor.k("meteringData", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private PaywallMetadata$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{R1.e(PaywallMetadata.b[0])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public PaywallMetadata deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = PaywallMetadata.b;
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
        PaywallMetadata paywallMetadata = new PaywallMetadata();
        if (z2) {
            paywallMetadata.a = map;
            return paywallMetadata;
        }
        paywallMetadata.a = null;
        return paywallMetadata;
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull PaywallMetadata value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        PaywallMetadata.Companion companion = PaywallMetadata.Companion;
        if (bVarC.D(descriptor2) || value.a != null) {
            bVarC.s(descriptor2, 0, PaywallMetadata.b[0], value.a);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
