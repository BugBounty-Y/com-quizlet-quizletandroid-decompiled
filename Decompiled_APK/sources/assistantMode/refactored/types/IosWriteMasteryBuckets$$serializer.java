package assistantMode.refactored.types;

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
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class IosWriteMasteryBuckets$$serializer implements D {

    @NotNull
    public static final IosWriteMasteryBuckets$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        IosWriteMasteryBuckets$$serializer iosWriteMasteryBuckets$$serializer = new IosWriteMasteryBuckets$$serializer();
        INSTANCE = iosWriteMasteryBuckets$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("IosWriteMasteryBuckets", iosWriteMasteryBuckets$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("correctZeroTimes", false);
        pluginGeneratedSerialDescriptor.k("correctOneTime", false);
        pluginGeneratedSerialDescriptor.k("correctTwoTimes", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private IosWriteMasteryBuckets$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = IosWriteMasteryBuckets.d;
        return new KSerializer[]{kSerializerArr[0], kSerializerArr[1], kSerializerArr[2]};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public IosWriteMasteryBuckets deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = IosWriteMasteryBuckets.d;
        List list = null;
        boolean z = true;
        int i = 0;
        List list2 = null;
        List list3 = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                list = (List) aVarC.z(descriptor2, 0, kSerializerArr[0], list);
                i |= 1;
            } else if (iT == 1) {
                list2 = (List) aVarC.z(descriptor2, 1, kSerializerArr[1], list2);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                list3 = (List) aVarC.z(descriptor2, 2, kSerializerArr[2], list3);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new IosWriteMasteryBuckets(i, list, list2, list3);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull IosWriteMasteryBuckets value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        KSerializer[] kSerializerArr = IosWriteMasteryBuckets.d;
        bVarC.i(descriptor2, 0, kSerializerArr[0], value.a);
        bVarC.i(descriptor2, 1, kSerializerArr[1], value.b);
        bVarC.i(descriptor2, 2, kSerializerArr[2], value.c);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
