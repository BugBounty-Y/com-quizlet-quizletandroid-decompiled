package assistantMode.refactored.types;

import assistantMode.enums.j;
import assistantMode.enums.k;
import assistantMode.types.QuestionMetadata;
import assistantMode.types.QuestionMetadata$$serializer;
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
public final class SeparatedOptionMatchingQuestion$$serializer implements D {

    @NotNull
    public static final SeparatedOptionMatchingQuestion$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        SeparatedOptionMatchingQuestion$$serializer separatedOptionMatchingQuestion$$serializer = new SeparatedOptionMatchingQuestion$$serializer();
        INSTANCE = separatedOptionMatchingQuestion$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("SeparatedOptionMatchingQuestion", separatedOptionMatchingQuestion$$serializer, 4);
        pluginGeneratedSerialDescriptor.k("prompts", false);
        pluginGeneratedSerialDescriptor.k("options", false);
        pluginGeneratedSerialDescriptor.k("metadata", false);
        pluginGeneratedSerialDescriptor.k("questionType", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private SeparatedOptionMatchingQuestion$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = SeparatedOptionMatchingQuestion.e;
        return new KSerializer[]{kSerializerArr[0], kSerializerArr[1], QuestionMetadata$$serializer.INSTANCE, j.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SeparatedOptionMatchingQuestion deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = SeparatedOptionMatchingQuestion.e;
        int i = 0;
        List list = null;
        List list2 = null;
        QuestionMetadata questionMetadata = null;
        k kVar = null;
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
                questionMetadata = (QuestionMetadata) aVarC.z(descriptor2, 2, QuestionMetadata$$serializer.INSTANCE, questionMetadata);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                kVar = (k) aVarC.z(descriptor2, 3, j.f, kVar);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new SeparatedOptionMatchingQuestion(i, list, list2, questionMetadata, kVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull SeparatedOptionMatchingQuestion value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        KSerializer[] kSerializerArr = SeparatedOptionMatchingQuestion.e;
        bVarC.i(descriptor2, 0, kSerializerArr[0], value.a);
        bVarC.i(descriptor2, 1, kSerializerArr[1], value.b);
        bVarC.i(descriptor2, 2, QuestionMetadata$$serializer.INSTANCE, value.c);
        boolean zD = bVarC.D(descriptor2);
        k kVar = value.d;
        if (zD || kVar != k.c) {
            bVarC.i(descriptor2, 3, j.f, kVar);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
