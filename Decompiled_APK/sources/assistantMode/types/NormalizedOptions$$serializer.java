package assistantMode.types;

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
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class NormalizedOptions$$serializer implements kotlinx.serialization.internal.D {

    @NotNull
    public static final NormalizedOptions$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        NormalizedOptions$$serializer normalizedOptions$$serializer = new NormalizedOptions$$serializer();
        INSTANCE = normalizedOptions$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.types.NormalizedOptions", normalizedOptions$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("enabledQuestionTypes", false);
        pluginGeneratedSerialDescriptor.k("enabledPromptSides", false);
        pluginGeneratedSerialDescriptor.k("enabledAnswerSides", false);
        pluginGeneratedSerialDescriptor.k("enabledWrittenAnswerSides", false);
        pluginGeneratedSerialDescriptor.k("enabledLocationQuestionTypes", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private NormalizedOptions$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = NormalizedOptions.f;
        return new KSerializer[]{kSerializerArr[0], kSerializerArr[1], kSerializerArr[2], kSerializerArr[3], kSerializerArr[4]};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public NormalizedOptions deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = NormalizedOptions.f;
        int i = 0;
        List list = null;
        List list2 = null;
        List list3 = null;
        List list4 = null;
        List list5 = null;
        boolean z = true;
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
            } else if (iT == 2) {
                list3 = (List) aVarC.z(descriptor2, 2, kSerializerArr[2], list3);
                i |= 4;
            } else if (iT == 3) {
                list4 = (List) aVarC.z(descriptor2, 3, kSerializerArr[3], list4);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                list5 = (List) aVarC.z(descriptor2, 4, kSerializerArr[4], list5);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new NormalizedOptions(i, list, list2, list3, list4, list5);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull NormalizedOptions value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        KSerializer[] kSerializerArr = NormalizedOptions.f;
        bVarC.i(descriptor2, 0, kSerializerArr[0], value.a);
        bVarC.i(descriptor2, 1, kSerializerArr[1], value.b);
        bVarC.i(descriptor2, 2, kSerializerArr[2], value.c);
        bVarC.i(descriptor2, 3, kSerializerArr[3], value.d);
        boolean zD = bVarC.D(descriptor2);
        List list = value.e;
        if (zD || !Intrinsics.b(list, value.a)) {
            bVarC.i(descriptor2, 4, kSerializerArr[4], list);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
