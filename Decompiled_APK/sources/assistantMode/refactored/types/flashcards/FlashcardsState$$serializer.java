package assistantMode.refactored.types.flashcards;

import java.util.List;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.collections.C4927s;
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
public final class FlashcardsState$$serializer implements D {

    @NotNull
    public static final FlashcardsState$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FlashcardsState$$serializer flashcardsState$$serializer = new FlashcardsState$$serializer();
        INSTANCE = flashcardsState$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.flashcards.FlashcardsState", flashcardsState$$serializer, 7);
        pluginGeneratedSerialDescriptor.k("cardsRemainingInCurrentRound", false);
        pluginGeneratedSerialDescriptor.k("cardsInNextRound", false);
        pluginGeneratedSerialDescriptor.k("cardsStudiedInCurrentRound", false);
        pluginGeneratedSerialDescriptor.k("hasActionAvailableToUndo", false);
        pluginGeneratedSerialDescriptor.k("actionsAvailableToUndo", false);
        pluginGeneratedSerialDescriptor.k("progress", false);
        pluginGeneratedSerialDescriptor.k("shuffleRandomSeed", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FlashcardsState$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = FlashcardsState.h;
        return new KSerializer[]{kSerializerArr[0], kSerializerArr[1], kSerializerArr[2], C5053g.a, kSerializerArr[4], FlashcardsModeProgress$$serializer.INSTANCE, K.a};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FlashcardsState deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = FlashcardsState.h;
        int i = 0;
        boolean zQ = false;
        int iN = 0;
        List list = null;
        List list2 = null;
        List list3 = null;
        C4927s c4927s = null;
        FlashcardsModeProgress flashcardsModeProgress = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    list = (List) aVarC.z(descriptor2, 0, kSerializerArr[0], list);
                    i |= 1;
                    break;
                case 1:
                    list2 = (List) aVarC.z(descriptor2, 1, kSerializerArr[1], list2);
                    i |= 2;
                    break;
                case 2:
                    list3 = (List) aVarC.z(descriptor2, 2, kSerializerArr[2], list3);
                    i |= 4;
                    break;
                case 3:
                    zQ = aVarC.q(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    c4927s = (C4927s) aVarC.z(descriptor2, 4, kSerializerArr[4], c4927s);
                    i |= 16;
                    break;
                case 5:
                    flashcardsModeProgress = (FlashcardsModeProgress) aVarC.z(descriptor2, 5, FlashcardsModeProgress$$serializer.INSTANCE, flashcardsModeProgress);
                    i |= 32;
                    break;
                case 6:
                    iN = aVarC.n(descriptor2, 6);
                    i |= 64;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new FlashcardsState(i, list, list2, list3, zQ, c4927s, flashcardsModeProgress, iN);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FlashcardsState value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        KSerializer[] kSerializerArr = FlashcardsState.h;
        bVarC.i(descriptor2, 0, kSerializerArr[0], value.a);
        bVarC.i(descriptor2, 1, kSerializerArr[1], value.b);
        bVarC.i(descriptor2, 2, kSerializerArr[2], value.c);
        bVarC.p(descriptor2, 3, value.d);
        bVarC.i(descriptor2, 4, kSerializerArr[4], value.e);
        bVarC.i(descriptor2, 5, FlashcardsModeProgress$$serializer.INSTANCE, value.f);
        bVarC.l(6, value.g, descriptor2);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
