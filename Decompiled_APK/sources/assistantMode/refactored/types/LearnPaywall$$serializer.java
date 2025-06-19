package assistantMode.refactored.types;

import assistantMode.types.PaywallMetadata;
import assistantMode.types.PaywallMetadata$$serializer;
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
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class LearnPaywall$$serializer implements D {

    @NotNull
    public static final LearnPaywall$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        LearnPaywall$$serializer learnPaywall$$serializer = new LearnPaywall$$serializer();
        INSTANCE = learnPaywall$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("LearnPaywall", learnPaywall$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("checkpoint", false);
        pluginGeneratedSerialDescriptor.k("metadata", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private LearnPaywall$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{R1.e(Checkpoint$$serializer.INSTANCE), PaywallMetadata$$serializer.INSTANCE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public LearnPaywall deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        Checkpoint checkpoint = null;
        boolean z = true;
        int i = 0;
        PaywallMetadata paywallMetadata = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                checkpoint = (Checkpoint) aVarC.v(descriptor2, 0, Checkpoint$$serializer.INSTANCE, checkpoint);
                i |= 1;
            } else {
                if (iT != 1) {
                    throw new UnknownFieldException(iT);
                }
                paywallMetadata = (PaywallMetadata) aVarC.z(descriptor2, 1, PaywallMetadata$$serializer.INSTANCE, paywallMetadata);
                i |= 2;
            }
        }
        aVarC.b(descriptor2);
        return new LearnPaywall(i, checkpoint, paywallMetadata);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull LearnPaywall value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.s(descriptor2, 0, Checkpoint$$serializer.INSTANCE, value.a);
        boolean zD = bVarC.D(descriptor2);
        PaywallMetadata paywallMetadata = value.b;
        if (zD || !Intrinsics.b(paywallMetadata, new PaywallMetadata())) {
            bVarC.i(descriptor2, 1, PaywallMetadata$$serializer.INSTANCE, paywallMetadata);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
