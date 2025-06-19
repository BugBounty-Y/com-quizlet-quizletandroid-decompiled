package assistantMode.refactored.types.flashcards;

import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion$$serializer;
import assistantMode.refactored.types.flashcards.FlashcardsQuestion;
import assistantMode.types.FlashcardsStepMetadata;
import assistantMode.types.FlashcardsStepMetadata$$serializer;
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
public final class FlashcardsQuestion$$serializer implements D {

    @NotNull
    public static final FlashcardsQuestion$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FlashcardsQuestion$$serializer flashcardsQuestion$$serializer = new FlashcardsQuestion$$serializer();
        INSTANCE = flashcardsQuestion$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FlashcardsQuestion", flashcardsQuestion$$serializer, 4);
        pluginGeneratedSerialDescriptor.k("question", false);
        pluginGeneratedSerialDescriptor.k("lastAction", false);
        pluginGeneratedSerialDescriptor.k("progress", false);
        pluginGeneratedSerialDescriptor.k("metadata", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FlashcardsQuestion$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{RevealSelfAssessmentQuestion$$serializer.INSTANCE, FlashcardsQuestion.e[1], FlashcardsModeProgress$$serializer.INSTANCE, FlashcardsStepMetadata$$serializer.INSTANCE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FlashcardsQuestion deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = FlashcardsQuestion.e;
        int i = 0;
        RevealSelfAssessmentQuestion revealSelfAssessmentQuestion = null;
        a aVar = null;
        FlashcardsModeProgress flashcardsModeProgress = null;
        FlashcardsStepMetadata flashcardsStepMetadata = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                revealSelfAssessmentQuestion = (RevealSelfAssessmentQuestion) aVarC.z(descriptor2, 0, RevealSelfAssessmentQuestion$$serializer.INSTANCE, revealSelfAssessmentQuestion);
                i |= 1;
            } else if (iT == 1) {
                aVar = (a) aVarC.z(descriptor2, 1, kSerializerArr[1], aVar);
                i |= 2;
            } else if (iT == 2) {
                flashcardsModeProgress = (FlashcardsModeProgress) aVarC.z(descriptor2, 2, FlashcardsModeProgress$$serializer.INSTANCE, flashcardsModeProgress);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                flashcardsStepMetadata = (FlashcardsStepMetadata) aVarC.z(descriptor2, 3, FlashcardsStepMetadata$$serializer.INSTANCE, flashcardsStepMetadata);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new FlashcardsQuestion(i, revealSelfAssessmentQuestion, aVar, flashcardsModeProgress, flashcardsStepMetadata);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FlashcardsQuestion value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        FlashcardsQuestion.Companion companion = FlashcardsQuestion.Companion;
        bVarC.i(descriptor2, 0, RevealSelfAssessmentQuestion$$serializer.INSTANCE, value.a);
        bVarC.i(descriptor2, 1, FlashcardsQuestion.e[1], value.b);
        bVarC.i(descriptor2, 2, FlashcardsModeProgress$$serializer.INSTANCE, value.c);
        bVarC.i(descriptor2, 3, FlashcardsStepMetadata$$serializer.INSTANCE, value.d);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
