package assistantMode.refactored.types;

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
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class AdsSettings$$serializer implements D {

    @NotNull
    public static final AdsSettings$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        AdsSettings$$serializer adsSettings$$serializer = new AdsSettings$$serializer();
        INSTANCE = adsSettings$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.AdsSettings", adsSettings$$serializer, 4);
        pluginGeneratedSerialDescriptor.k("numCardsToShowAds", false);
        pluginGeneratedSerialDescriptor.k("numCardsPriorToPreloadAds", true);
        pluginGeneratedSerialDescriptor.k("minShownInterval", true);
        pluginGeneratedSerialDescriptor.k("maxNumAds", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private AdsSettings$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        K k = K.a;
        return new KSerializer[]{k, k, R1.e(k), R1.e(k)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public AdsSettings deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        int iN = 0;
        int iN2 = 0;
        Integer num = null;
        Integer num2 = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                iN = aVarC.n(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                iN2 = aVarC.n(descriptor2, 1);
                i |= 2;
            } else if (iT == 2) {
                num = (Integer) aVarC.v(descriptor2, 2, K.a, num);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                num2 = (Integer) aVarC.v(descriptor2, 3, K.a, num2);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new AdsSettings(i, iN, iN2, num, num2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull AdsSettings value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.l(0, value.a, descriptor2);
        boolean zD = bVarC.D(descriptor2);
        int i = value.b;
        if (zD || i != 2) {
            bVarC.l(1, i, descriptor2);
        }
        boolean zD2 = bVarC.D(descriptor2);
        Integer num = value.c;
        if (zD2 || num != null) {
            bVarC.s(descriptor2, 2, K.a, num);
        }
        boolean zD3 = bVarC.D(descriptor2);
        Integer num2 = value.d;
        if (zD3 || num2 != null) {
            bVarC.s(descriptor2, 3, K.a, num2);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
