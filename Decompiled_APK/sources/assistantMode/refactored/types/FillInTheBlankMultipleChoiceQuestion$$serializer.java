package assistantMode.refactored.types;

import assistantMode.enums.j;
import assistantMode.enums.k;
import assistantMode.refactored.types.FillInTheBlankMultipleChoiceQuestion;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionElement$$serializer;
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
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class FillInTheBlankMultipleChoiceQuestion$$serializer implements D {

    @NotNull
    public static final FillInTheBlankMultipleChoiceQuestion$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FillInTheBlankMultipleChoiceQuestion$$serializer fillInTheBlankMultipleChoiceQuestion$$serializer = new FillInTheBlankMultipleChoiceQuestion$$serializer();
        INSTANCE = fillInTheBlankMultipleChoiceQuestion$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FillInTheBlankMultipleChoiceQuestion", fillInTheBlankMultipleChoiceQuestion$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("prompt", false);
        pluginGeneratedSerialDescriptor.k("segments", false);
        pluginGeneratedSerialDescriptor.k("isMulti", false);
        pluginGeneratedSerialDescriptor.k("metadata", false);
        pluginGeneratedSerialDescriptor.k("questionType", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FillInTheBlankMultipleChoiceQuestion$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{QuestionElement$$serializer.INSTANCE, FillInTheBlankMultipleChoiceQuestion.f[1], C5053g.a, QuestionMetadata$$serializer.INSTANCE, j.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FillInTheBlankMultipleChoiceQuestion deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = FillInTheBlankMultipleChoiceQuestion.f;
        int i = 0;
        boolean zQ = false;
        QuestionElement questionElement = null;
        List list = null;
        QuestionMetadata questionMetadata = null;
        k kVar = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                questionElement = (QuestionElement) aVarC.z(descriptor2, 0, QuestionElement$$serializer.INSTANCE, questionElement);
                i |= 1;
            } else if (iT == 1) {
                list = (List) aVarC.z(descriptor2, 1, kSerializerArr[1], list);
                i |= 2;
            } else if (iT == 2) {
                zQ = aVarC.q(descriptor2, 2);
                i |= 4;
            } else if (iT == 3) {
                questionMetadata = (QuestionMetadata) aVarC.z(descriptor2, 3, QuestionMetadata$$serializer.INSTANCE, questionMetadata);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                kVar = (k) aVarC.z(descriptor2, 4, j.f, kVar);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new FillInTheBlankMultipleChoiceQuestion(i, questionElement, list, zQ, questionMetadata, kVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FillInTheBlankMultipleChoiceQuestion value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        FillInTheBlankMultipleChoiceQuestion.Companion companion = FillInTheBlankMultipleChoiceQuestion.Companion;
        bVarC.i(descriptor2, 0, QuestionElement$$serializer.INSTANCE, value.a);
        bVarC.i(descriptor2, 1, FillInTheBlankMultipleChoiceQuestion.f[1], value.b);
        bVarC.p(descriptor2, 2, value.c);
        bVarC.i(descriptor2, 3, QuestionMetadata$$serializer.INSTANCE, value.d);
        boolean zD = bVarC.D(descriptor2);
        k kVar = value.e;
        if (zD || kVar != k.n) {
            bVarC.i(descriptor2, 4, j.f, kVar);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
