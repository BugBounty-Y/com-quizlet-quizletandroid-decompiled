package assistantMode.refactored.types;

import assistantMode.enums.j;
import assistantMode.enums.k;
import assistantMode.refactored.types.MultipleChoiceQuestion;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionElement$$serializer;
import assistantMode.types.QuestionMetadata;
import assistantMode.types.QuestionMetadata$$serializer;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
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
public final class MultipleChoiceQuestion$$serializer implements D {

    @NotNull
    public static final MultipleChoiceQuestion$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        MultipleChoiceQuestion$$serializer multipleChoiceQuestion$$serializer = new MultipleChoiceQuestion$$serializer();
        INSTANCE = multipleChoiceQuestion$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("MultipleChoiceQuestion", multipleChoiceQuestion$$serializer, 6);
        pluginGeneratedSerialDescriptor.k("prompt", false);
        pluginGeneratedSerialDescriptor.k("hint", false);
        pluginGeneratedSerialDescriptor.k("options", false);
        pluginGeneratedSerialDescriptor.k("hasExactlyOneCorrectAnswer", false);
        pluginGeneratedSerialDescriptor.k("metadata", false);
        pluginGeneratedSerialDescriptor.k("questionType", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private MultipleChoiceQuestion$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = MultipleChoiceQuestion.g;
        QuestionElement$$serializer questionElement$$serializer = QuestionElement$$serializer.INSTANCE;
        return new KSerializer[]{questionElement$$serializer, R1.e(questionElement$$serializer), kSerializerArr[2], C5053g.a, QuestionMetadata$$serializer.INSTANCE, j.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public MultipleChoiceQuestion deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = MultipleChoiceQuestion.g;
        int i = 0;
        boolean zQ = false;
        QuestionElement questionElement = null;
        QuestionElement questionElement2 = null;
        List list = null;
        QuestionMetadata questionMetadata = null;
        k kVar = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    questionElement = (QuestionElement) aVarC.z(descriptor2, 0, QuestionElement$$serializer.INSTANCE, questionElement);
                    i |= 1;
                    break;
                case 1:
                    questionElement2 = (QuestionElement) aVarC.v(descriptor2, 1, QuestionElement$$serializer.INSTANCE, questionElement2);
                    i |= 2;
                    break;
                case 2:
                    list = (List) aVarC.z(descriptor2, 2, kSerializerArr[2], list);
                    i |= 4;
                    break;
                case 3:
                    zQ = aVarC.q(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    questionMetadata = (QuestionMetadata) aVarC.z(descriptor2, 4, QuestionMetadata$$serializer.INSTANCE, questionMetadata);
                    i |= 16;
                    break;
                case 5:
                    kVar = (k) aVarC.z(descriptor2, 5, j.f, kVar);
                    i |= 32;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new MultipleChoiceQuestion(i, questionElement, questionElement2, list, zQ, questionMetadata, kVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull MultipleChoiceQuestion value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        MultipleChoiceQuestion.Companion companion = MultipleChoiceQuestion.Companion;
        QuestionElement$$serializer questionElement$$serializer = QuestionElement$$serializer.INSTANCE;
        bVarC.i(descriptor2, 0, questionElement$$serializer, value.a);
        bVarC.s(descriptor2, 1, questionElement$$serializer, value.b);
        bVarC.i(descriptor2, 2, MultipleChoiceQuestion.g[2], value.c);
        bVarC.p(descriptor2, 3, value.d);
        bVarC.i(descriptor2, 4, QuestionMetadata$$serializer.INSTANCE, value.e);
        boolean zD = bVarC.D(descriptor2);
        k kVar = value.f;
        if (zD || kVar != k.d) {
            bVarC.i(descriptor2, 5, j.f, kVar);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
