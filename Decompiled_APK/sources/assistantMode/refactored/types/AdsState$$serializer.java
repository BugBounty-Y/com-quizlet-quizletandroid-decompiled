package assistantMode.refactored.types;

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
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class AdsState$$serializer implements D {

    @NotNull
    public static final AdsState$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        AdsState$$serializer adsState$$serializer = new AdsState$$serializer();
        INSTANCE = adsState$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.AdsState", adsState$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("shouldShowAds", false);
        pluginGeneratedSerialDescriptor.k("shouldPreloadAds", false);
        pluginGeneratedSerialDescriptor.k("hasExceedsMaxNumAdsShown", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private AdsState$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{c5053g, c5053g, c5053g};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public AdsState deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        boolean z = true;
        int i = 0;
        boolean zQ = false;
        boolean zQ2 = false;
        boolean zQ3 = false;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                zQ = aVarC.q(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                zQ2 = aVarC.q(descriptor2, 1);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                zQ3 = aVarC.q(descriptor2, 2);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new AdsState(i, zQ, zQ2, zQ3);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull AdsState value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.p(descriptor2, 0, value.a);
        bVarC.p(descriptor2, 1, value.b);
        bVarC.p(descriptor2, 2, value.c);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
