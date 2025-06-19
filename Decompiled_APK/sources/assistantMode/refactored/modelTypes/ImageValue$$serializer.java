package assistantMode.refactored.modelTypes;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
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
public final class ImageValue$$serializer implements D {

    @NotNull
    public static final ImageValue$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        ImageValue$$serializer imageValue$$serializer = new ImageValue$$serializer();
        INSTANCE = imageValue$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("2", imageValue$$serializer, 3);
        pluginGeneratedSerialDescriptor.k(DTBMetricsConfiguration.APSMETRICS_URL, false);
        pluginGeneratedSerialDescriptor.k(OTUXParamsKeys.OT_UX_WIDTH, false);
        pluginGeneratedSerialDescriptor.k(OTUXParamsKeys.OT_UX_HEIGHT, false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private ImageValue$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        K k = K.a;
        return new KSerializer[]{q0.a, k, k};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public ImageValue deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        String strR = null;
        boolean z = true;
        int i = 0;
        int iN = 0;
        int iN2 = 0;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                strR = aVarC.r(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                iN = aVarC.n(descriptor2, 1);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                iN2 = aVarC.n(descriptor2, 2);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new ImageValue(i, iN, strR, iN2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull ImageValue value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.a);
        bVarC.l(1, value.b, descriptor2);
        bVarC.l(2, value.c, descriptor2);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
