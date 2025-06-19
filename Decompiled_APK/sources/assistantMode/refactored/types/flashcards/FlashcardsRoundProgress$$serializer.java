package assistantMode.refactored.types.flashcards;

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
import kotlinx.serialization.internal.C5067v;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class FlashcardsRoundProgress$$serializer implements D {

    @NotNull
    public static final FlashcardsRoundProgress$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FlashcardsRoundProgress$$serializer flashcardsRoundProgress$$serializer = new FlashcardsRoundProgress$$serializer();
        INSTANCE = flashcardsRoundProgress$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.flashcards.FlashcardsRoundProgress", flashcardsRoundProgress$$serializer, 8);
        pluginGeneratedSerialDescriptor.k("isRoundComplete", false);
        pluginGeneratedSerialDescriptor.k("isCycleComplete", false);
        pluginGeneratedSerialDescriptor.k("numCardsCompleted", false);
        pluginGeneratedSerialDescriptor.k("totalNumCardsCompleted", false);
        pluginGeneratedSerialDescriptor.k("numCardsMovedToNextCycle", false);
        pluginGeneratedSerialDescriptor.k("totalNumCardsMovedToNextCycle", false);
        pluginGeneratedSerialDescriptor.k("numCards", false);
        pluginGeneratedSerialDescriptor.k("roundProgressPercent", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FlashcardsRoundProgress$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        C5053g c5053g = C5053g.a;
        K k = K.a;
        return new KSerializer[]{c5053g, c5053g, k, k, k, k, k, C5067v.a};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FlashcardsRoundProgress deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        boolean zQ = false;
        boolean zQ2 = false;
        int iN = 0;
        int iN2 = 0;
        int iN3 = 0;
        int iN4 = 0;
        int iN5 = 0;
        double dY = 0.0d;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    zQ = aVarC.q(descriptor2, 0);
                    i |= 1;
                    break;
                case 1:
                    zQ2 = aVarC.q(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    iN = aVarC.n(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    iN2 = aVarC.n(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    iN3 = aVarC.n(descriptor2, 4);
                    i |= 16;
                    break;
                case 5:
                    iN4 = aVarC.n(descriptor2, 5);
                    i |= 32;
                    break;
                case 6:
                    iN5 = aVarC.n(descriptor2, 6);
                    i |= 64;
                    break;
                case 7:
                    dY = aVarC.y(descriptor2, 7);
                    i |= 128;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new FlashcardsRoundProgress(i, zQ, zQ2, iN, iN2, iN3, iN4, iN5, dY);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FlashcardsRoundProgress value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.p(descriptor2, 0, value.a);
        bVarC.p(descriptor2, 1, value.b);
        bVarC.l(2, value.c, descriptor2);
        bVarC.l(3, value.d, descriptor2);
        bVarC.l(4, value.e, descriptor2);
        bVarC.l(5, value.f, descriptor2);
        bVarC.l(6, value.g, descriptor2);
        bVarC.A(descriptor2, 7, value.h);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
