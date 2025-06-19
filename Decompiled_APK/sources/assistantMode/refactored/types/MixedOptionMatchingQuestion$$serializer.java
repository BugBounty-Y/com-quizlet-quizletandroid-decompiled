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
public final class MixedOptionMatchingQuestion$$serializer implements D {

    @NotNull
    public static final MixedOptionMatchingQuestion$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        MixedOptionMatchingQuestion$$serializer mixedOptionMatchingQuestion$$serializer = new MixedOptionMatchingQuestion$$serializer();
        INSTANCE = mixedOptionMatchingQuestion$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("MixedOptionMatchingQuestion", mixedOptionMatchingQuestion$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("options", false);
        pluginGeneratedSerialDescriptor.k("metadata", false);
        pluginGeneratedSerialDescriptor.k("questionType", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private MixedOptionMatchingQuestion$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{MixedOptionMatchingQuestion.d[0], QuestionMetadata$$serializer.INSTANCE, j.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public MixedOptionMatchingQuestion deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = MixedOptionMatchingQuestion.d;
        List list = null;
        boolean z = true;
        int i = 0;
        QuestionMetadata questionMetadata = null;
        k kVar = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                list = (List) aVarC.z(descriptor2, 0, kSerializerArr[0], list);
                i |= 1;
            } else if (iT == 1) {
                questionMetadata = (QuestionMetadata) aVarC.z(descriptor2, 1, QuestionMetadata$$serializer.INSTANCE, questionMetadata);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                kVar = (k) aVarC.z(descriptor2, 2, j.f, kVar);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new MixedOptionMatchingQuestion(i, list, questionMetadata, kVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull MixedOptionMatchingQuestion value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, MixedOptionMatchingQuestion.d[0], value.a);
        bVarC.i(descriptor2, 1, QuestionMetadata$$serializer.INSTANCE, value.b);
        boolean zD = bVarC.D(descriptor2);
        k kVar = value.c;
        if (zD || kVar != k.k) {
            bVarC.i(descriptor2, 2, j.f, kVar);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
