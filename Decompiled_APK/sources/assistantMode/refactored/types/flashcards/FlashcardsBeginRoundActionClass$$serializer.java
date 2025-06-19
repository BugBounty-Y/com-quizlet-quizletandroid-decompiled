package assistantMode.refactored.types.flashcards;

import assistantMode.refactored.types.flashcards.FlashcardsBeginRoundActionClass;
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
public final class FlashcardsBeginRoundActionClass$$serializer implements D {

    @NotNull
    public static final FlashcardsBeginRoundActionClass$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FlashcardsBeginRoundActionClass$$serializer flashcardsBeginRoundActionClass$$serializer = new FlashcardsBeginRoundActionClass$$serializer();
        INSTANCE = flashcardsBeginRoundActionClass$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FlashcardsBeginRoundAction", flashcardsBeginRoundActionClass$$serializer, 1);
        pluginGeneratedSerialDescriptor.k("nothing", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FlashcardsBeginRoundActionClass$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{R1.e(FlashcardsBeginRoundActionClass.b[0])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FlashcardsBeginRoundActionClass deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = FlashcardsBeginRoundActionClass.b;
        Object objV = null;
        boolean z = true;
        int i = 0;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else {
                if (iT != 0) {
                    throw new UnknownFieldException(iT);
                }
                objV = aVarC.v(descriptor2, 0, kSerializerArr[0], objV);
                i = 1;
            }
        }
        aVarC.b(descriptor2);
        return new FlashcardsBeginRoundActionClass(i, objV);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FlashcardsBeginRoundActionClass value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        FlashcardsBeginRoundActionClass.Companion companion = FlashcardsBeginRoundActionClass.Companion;
        if (bVarC.D(descriptor2) || value.a != null) {
            bVarC.s(descriptor2, 0, FlashcardsBeginRoundActionClass.b[0], value.a);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
