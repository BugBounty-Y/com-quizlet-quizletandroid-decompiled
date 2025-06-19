package assistantMode.refactored.types.flashcards;

import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion$$serializer;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
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
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class ExternalFlashcardsState$$serializer implements D {

    @NotNull
    public static final ExternalFlashcardsState$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        ExternalFlashcardsState$$serializer externalFlashcardsState$$serializer = new ExternalFlashcardsState$$serializer();
        INSTANCE = externalFlashcardsState$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.flashcards.ExternalFlashcardsState", externalFlashcardsState$$serializer, 4);
        pluginGeneratedSerialDescriptor.k("question", false);
        pluginGeneratedSerialDescriptor.k("hasActionAvailableToUndo", false);
        pluginGeneratedSerialDescriptor.k("progress", false);
        pluginGeneratedSerialDescriptor.k("shuffleRandomSeed", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private ExternalFlashcardsState$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{R1.e(RevealSelfAssessmentQuestion$$serializer.INSTANCE), C5053g.a, FlashcardsModeProgress$$serializer.INSTANCE, K.a};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public ExternalFlashcardsState deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        boolean zQ = false;
        int iN = 0;
        RevealSelfAssessmentQuestion revealSelfAssessmentQuestion = null;
        FlashcardsModeProgress flashcardsModeProgress = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                revealSelfAssessmentQuestion = (RevealSelfAssessmentQuestion) aVarC.v(descriptor2, 0, RevealSelfAssessmentQuestion$$serializer.INSTANCE, revealSelfAssessmentQuestion);
                i |= 1;
            } else if (iT == 1) {
                zQ = aVarC.q(descriptor2, 1);
                i |= 2;
            } else if (iT == 2) {
                flashcardsModeProgress = (FlashcardsModeProgress) aVarC.z(descriptor2, 2, FlashcardsModeProgress$$serializer.INSTANCE, flashcardsModeProgress);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                iN = aVarC.n(descriptor2, 3);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new ExternalFlashcardsState(i, revealSelfAssessmentQuestion, zQ, flashcardsModeProgress, iN);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull ExternalFlashcardsState value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.s(descriptor2, 0, RevealSelfAssessmentQuestion$$serializer.INSTANCE, value.a);
        bVarC.p(descriptor2, 1, value.b);
        bVarC.i(descriptor2, 2, FlashcardsModeProgress$$serializer.INSTANCE, value.c);
        bVarC.l(3, value.d, descriptor2);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
