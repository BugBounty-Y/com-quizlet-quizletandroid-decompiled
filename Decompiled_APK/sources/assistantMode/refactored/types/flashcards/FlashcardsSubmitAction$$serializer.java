package assistantMode.refactored.types.flashcards;

import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion$$serializer;
import assistantMode.refactored.types.flashcards.FlashcardsSubmitAction;
import assistantMode.types.RevealSelfAssessmentAnswer;
import assistantMode.types.RevealSelfAssessmentAnswer$$serializer;
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
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class FlashcardsSubmitAction$$serializer implements D {

    @NotNull
    public static final FlashcardsSubmitAction$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FlashcardsSubmitAction$$serializer flashcardsSubmitAction$$serializer = new FlashcardsSubmitAction$$serializer();
        INSTANCE = flashcardsSubmitAction$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FlashcardsSubmitAction", flashcardsSubmitAction$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("question", false);
        pluginGeneratedSerialDescriptor.k("answer", false);
        pluginGeneratedSerialDescriptor.k("clientData", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FlashcardsSubmitAction$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{RevealSelfAssessmentQuestion$$serializer.INSTANCE, RevealSelfAssessmentAnswer$$serializer.INSTANCE, R1.e(FlashcardsSubmitAction.d[2])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FlashcardsSubmitAction deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = FlashcardsSubmitAction.d;
        RevealSelfAssessmentQuestion revealSelfAssessmentQuestion = null;
        boolean z = true;
        int i = 0;
        RevealSelfAssessmentAnswer revealSelfAssessmentAnswer = null;
        Object objV = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                revealSelfAssessmentQuestion = (RevealSelfAssessmentQuestion) aVarC.z(descriptor2, 0, RevealSelfAssessmentQuestion$$serializer.INSTANCE, revealSelfAssessmentQuestion);
                i |= 1;
            } else if (iT == 1) {
                revealSelfAssessmentAnswer = (RevealSelfAssessmentAnswer) aVarC.z(descriptor2, 1, RevealSelfAssessmentAnswer$$serializer.INSTANCE, revealSelfAssessmentAnswer);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                objV = aVarC.v(descriptor2, 2, kSerializerArr[2], objV);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new FlashcardsSubmitAction(i, revealSelfAssessmentQuestion, revealSelfAssessmentAnswer, objV);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FlashcardsSubmitAction value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        FlashcardsSubmitAction.Companion companion = FlashcardsSubmitAction.Companion;
        bVarC.i(descriptor2, 0, RevealSelfAssessmentQuestion$$serializer.INSTANCE, value.a);
        bVarC.i(descriptor2, 1, RevealSelfAssessmentAnswer$$serializer.INSTANCE, value.b);
        bVarC.s(descriptor2, 2, FlashcardsSubmitAction.d[2], value.c);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
