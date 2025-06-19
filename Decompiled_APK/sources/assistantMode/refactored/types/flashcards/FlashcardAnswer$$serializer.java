package assistantMode.refactored.types.flashcards;

import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion$$serializer;
import assistantMode.types.RevealSelfAssessmentAnswer;
import assistantMode.types.RevealSelfAssessmentAnswer$$serializer;
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
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class FlashcardAnswer$$serializer implements D {

    @NotNull
    public static final FlashcardAnswer$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FlashcardAnswer$$serializer flashcardAnswer$$serializer = new FlashcardAnswer$$serializer();
        INSTANCE = flashcardAnswer$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.flashcards.FlashcardAnswer", flashcardAnswer$$serializer, 4);
        pluginGeneratedSerialDescriptor.k("answer", false);
        pluginGeneratedSerialDescriptor.k("question", false);
        pluginGeneratedSerialDescriptor.k("roundNum", false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FlashcardAnswer$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{RevealSelfAssessmentAnswer$$serializer.INSTANCE, RevealSelfAssessmentQuestion$$serializer.INSTANCE, K.a, P.a};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FlashcardAnswer deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        int iN = 0;
        RevealSelfAssessmentAnswer revealSelfAssessmentAnswer = null;
        RevealSelfAssessmentQuestion revealSelfAssessmentQuestion = null;
        long j = 0;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                revealSelfAssessmentAnswer = (RevealSelfAssessmentAnswer) aVarC.z(descriptor2, 0, RevealSelfAssessmentAnswer$$serializer.INSTANCE, revealSelfAssessmentAnswer);
                i |= 1;
            } else if (iT == 1) {
                revealSelfAssessmentQuestion = (RevealSelfAssessmentQuestion) aVarC.z(descriptor2, 1, RevealSelfAssessmentQuestion$$serializer.INSTANCE, revealSelfAssessmentQuestion);
                i |= 2;
            } else if (iT == 2) {
                iN = aVarC.n(descriptor2, 2);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                j = aVarC.j(descriptor2, 3);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new FlashcardAnswer(i, revealSelfAssessmentAnswer, revealSelfAssessmentQuestion, iN, j);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FlashcardAnswer value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, RevealSelfAssessmentAnswer$$serializer.INSTANCE, value.a);
        bVarC.i(descriptor2, 1, RevealSelfAssessmentQuestion$$serializer.INSTANCE, value.b);
        bVarC.l(2, value.c, descriptor2);
        bVarC.C(descriptor2, 3, value.d);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
