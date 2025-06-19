package assistantMode.refactored.types.flashcards;

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
public final class FlashcardsModeSettings$$serializer implements D {

    @NotNull
    public static final FlashcardsModeSettings$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FlashcardsModeSettings$$serializer flashcardsModeSettings$$serializer = new FlashcardsModeSettings$$serializer();
        INSTANCE = flashcardsModeSettings$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.flashcards.FlashcardsModeSettings", flashcardsModeSettings$$serializer, 4);
        pluginGeneratedSerialDescriptor.k("frontCardSides", false);
        pluginGeneratedSerialDescriptor.k("rearCardSides", false);
        pluginGeneratedSerialDescriptor.k("cardOrdering", false);
        pluginGeneratedSerialDescriptor.k("isSortingEnabled", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FlashcardsModeSettings$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = FlashcardsModeSettings.e;
        return new KSerializer[]{kSerializerArr[0], kSerializerArr[1], com.quizlet.shared.enums.c.f, C5053g.a};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FlashcardsModeSettings deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = FlashcardsModeSettings.e;
        int i = 0;
        boolean zQ = false;
        List list = null;
        List list2 = null;
        com.quizlet.shared.enums.d dVar = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                list = (List) aVarC.z(descriptor2, 0, kSerializerArr[0], list);
                i |= 1;
            } else if (iT == 1) {
                list2 = (List) aVarC.z(descriptor2, 1, kSerializerArr[1], list2);
                i |= 2;
            } else if (iT == 2) {
                dVar = (com.quizlet.shared.enums.d) aVarC.z(descriptor2, 2, com.quizlet.shared.enums.c.f, dVar);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                zQ = aVarC.q(descriptor2, 3);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new FlashcardsModeSettings(i, list, list2, dVar, zQ);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FlashcardsModeSettings value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        KSerializer[] kSerializerArr = FlashcardsModeSettings.e;
        bVarC.i(descriptor2, 0, kSerializerArr[0], value.a);
        bVarC.i(descriptor2, 1, kSerializerArr[1], value.b);
        bVarC.i(descriptor2, 2, com.quizlet.shared.enums.c.f, value.c);
        bVarC.p(descriptor2, 3, value.d);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
