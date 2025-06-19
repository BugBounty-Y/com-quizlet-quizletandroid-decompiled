package assistantMode.refactored.types.flashcards;

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
public final class FlashcardsRoundSummary$$serializer implements D {

    @NotNull
    public static final FlashcardsRoundSummary$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FlashcardsRoundSummary$$serializer flashcardsRoundSummary$$serializer = new FlashcardsRoundSummary$$serializer();
        INSTANCE = flashcardsRoundSummary$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FlashcardsRoundSummary", flashcardsRoundSummary$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("lastAction", false);
        pluginGeneratedSerialDescriptor.k("progress", false);
        pluginGeneratedSerialDescriptor.k("metadata", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FlashcardsRoundSummary$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{FlashcardsRoundSummary.d[0], FlashcardsModeProgress$$serializer.INSTANCE, FlashcardsStepMetadata$$serializer.INSTANCE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FlashcardsRoundSummary deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = FlashcardsRoundSummary.d;
        a aVar = null;
        boolean z = true;
        int i = 0;
        FlashcardsModeProgress flashcardsModeProgress = null;
        FlashcardsStepMetadata flashcardsStepMetadata = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                aVar = (a) aVarC.z(descriptor2, 0, kSerializerArr[0], aVar);
                i |= 1;
            } else if (iT == 1) {
                flashcardsModeProgress = (FlashcardsModeProgress) aVarC.z(descriptor2, 1, FlashcardsModeProgress$$serializer.INSTANCE, flashcardsModeProgress);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                flashcardsStepMetadata = (FlashcardsStepMetadata) aVarC.z(descriptor2, 2, FlashcardsStepMetadata$$serializer.INSTANCE, flashcardsStepMetadata);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new FlashcardsRoundSummary(i, aVar, flashcardsModeProgress, flashcardsStepMetadata);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FlashcardsRoundSummary value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, FlashcardsRoundSummary.d[0], value.a);
        bVarC.i(descriptor2, 1, FlashcardsModeProgress$$serializer.INSTANCE, value.b);
        bVarC.i(descriptor2, 2, FlashcardsStepMetadata$$serializer.INSTANCE, value.c);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
