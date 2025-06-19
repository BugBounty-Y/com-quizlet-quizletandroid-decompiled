package assistantMode.refactored.modelTypes;

import assistantMode.refactored.enums.i;
import assistantMode.refactored.enums.j;
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
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class CustomMultipleChoiceQuestion$$serializer implements D {

    @NotNull
    public static final CustomMultipleChoiceQuestion$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        CustomMultipleChoiceQuestion$$serializer customMultipleChoiceQuestion$$serializer = new CustomMultipleChoiceQuestion$$serializer();
        INSTANCE = customMultipleChoiceQuestion$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("1", customMultipleChoiceQuestion$$serializer, 7);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerId", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerType", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k("promptMedia", false);
        pluginGeneratedSerialDescriptor.k("hintMedia", false);
        pluginGeneratedSerialDescriptor.k("options", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private CustomMultipleChoiceQuestion$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = CustomMultipleChoiceQuestion.h;
        KSerializer kSerializer = kSerializerArr[4];
        KSerializer kSerializer2 = kSerializerArr[5];
        KSerializer kSerializer3 = kSerializerArr[6];
        P p = P.a;
        return new KSerializer[]{p, p, i.f, p, kSerializer, kSerializer2, kSerializer3};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public CustomMultipleChoiceQuestion deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = CustomMultipleChoiceQuestion.h;
        List list = null;
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        List list2 = null;
        List list3 = null;
        j jVar = null;
        boolean z = true;
        int i = 0;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    j = aVarC.j(descriptor2, 0);
                    i |= 1;
                    break;
                case 1:
                    j2 = aVarC.j(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    jVar = (j) aVarC.z(descriptor2, 2, i.f, jVar);
                    i |= 4;
                    break;
                case 3:
                    j3 = aVarC.j(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    list = (List) aVarC.z(descriptor2, 4, kSerializerArr[4], list);
                    i |= 16;
                    break;
                case 5:
                    list2 = (List) aVarC.z(descriptor2, 5, kSerializerArr[5], list2);
                    i |= 32;
                    break;
                case 6:
                    list3 = (List) aVarC.z(descriptor2, 6, kSerializerArr[6], list3);
                    i |= 64;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new CustomMultipleChoiceQuestion(i, j, j2, jVar, j3, list, list2, list3);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull CustomMultipleChoiceQuestion value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.a);
        bVarC.C(descriptor2, 1, value.b);
        bVarC.i(descriptor2, 2, i.f, value.c);
        bVarC.C(descriptor2, 3, value.d);
        KSerializer[] kSerializerArr = CustomMultipleChoiceQuestion.h;
        bVarC.i(descriptor2, 4, kSerializerArr[4], value.e);
        bVarC.i(descriptor2, 5, kSerializerArr[5], value.f);
        bVarC.i(descriptor2, 6, kSerializerArr[6], value.g);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
