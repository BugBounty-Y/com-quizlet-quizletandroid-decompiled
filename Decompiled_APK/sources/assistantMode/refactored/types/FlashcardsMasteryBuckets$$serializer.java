package assistantMode.refactored.types;

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
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class FlashcardsMasteryBuckets$$serializer implements D {

    @NotNull
    public static final FlashcardsMasteryBuckets$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FlashcardsMasteryBuckets$$serializer flashcardsMasteryBuckets$$serializer = new FlashcardsMasteryBuckets$$serializer();
        INSTANCE = flashcardsMasteryBuckets$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FlashcardsMasteryBuckets", flashcardsMasteryBuckets$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("remaining", false);
        pluginGeneratedSerialDescriptor.k("completed", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FlashcardsMasteryBuckets$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = FlashcardsMasteryBuckets.c;
        return new KSerializer[]{kSerializerArr[0], kSerializerArr[1]};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FlashcardsMasteryBuckets deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = FlashcardsMasteryBuckets.c;
        List list = null;
        boolean z = true;
        int i = 0;
        List list2 = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                list = (List) aVarC.z(descriptor2, 0, kSerializerArr[0], list);
                i |= 1;
            } else {
                if (iT != 1) {
                    throw new UnknownFieldException(iT);
                }
                list2 = (List) aVarC.z(descriptor2, 1, kSerializerArr[1], list2);
                i |= 2;
            }
        }
        aVarC.b(descriptor2);
        return new FlashcardsMasteryBuckets(i, list, list2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FlashcardsMasteryBuckets value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        KSerializer[] kSerializerArr = FlashcardsMasteryBuckets.c;
        bVarC.i(descriptor2, 0, kSerializerArr[0], value.a);
        bVarC.i(descriptor2, 1, kSerializerArr[1], value.b);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
