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
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class FlashcardsProgressStats$$serializer implements D {

    @NotNull
    public static final FlashcardsProgressStats$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FlashcardsProgressStats$$serializer flashcardsProgressStats$$serializer = new FlashcardsProgressStats$$serializer();
        INSTANCE = flashcardsProgressStats$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.flashcards.FlashcardsProgressStats", flashcardsProgressStats$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("completed", false);
        pluginGeneratedSerialDescriptor.k("stillLearning", false);
        pluginGeneratedSerialDescriptor.k("total", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FlashcardsProgressStats$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        K k = K.a;
        return new KSerializer[]{k, k, k};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FlashcardsProgressStats deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        boolean z = true;
        int i = 0;
        int iN = 0;
        int iN2 = 0;
        int iN3 = 0;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                iN = aVarC.n(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                iN2 = aVarC.n(descriptor2, 1);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                iN3 = aVarC.n(descriptor2, 2);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new FlashcardsProgressStats(i, iN, iN2, iN3);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FlashcardsProgressStats value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.l(0, value.a, descriptor2);
        bVarC.l(1, value.b, descriptor2);
        bVarC.l(2, value.c, descriptor2);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
