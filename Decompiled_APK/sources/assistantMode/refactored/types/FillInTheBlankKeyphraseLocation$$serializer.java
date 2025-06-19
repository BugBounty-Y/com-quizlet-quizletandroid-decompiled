package assistantMode.refactored.types;

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
public final class FillInTheBlankKeyphraseLocation$$serializer implements D {

    @NotNull
    public static final FillInTheBlankKeyphraseLocation$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FillInTheBlankKeyphraseLocation$$serializer fillInTheBlankKeyphraseLocation$$serializer = new FillInTheBlankKeyphraseLocation$$serializer();
        INSTANCE = fillInTheBlankKeyphraseLocation$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.FillInTheBlankKeyphraseLocation", fillInTheBlankKeyphraseLocation$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("startIndex", false);
        pluginGeneratedSerialDescriptor.k("length", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FillInTheBlankKeyphraseLocation$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        K k = K.a;
        return new KSerializer[]{k, k};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FillInTheBlankKeyphraseLocation deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        boolean z = true;
        int i = 0;
        int iN = 0;
        int iN2 = 0;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                iN = aVarC.n(descriptor2, 0);
                i |= 1;
            } else {
                if (iT != 1) {
                    throw new UnknownFieldException(iT);
                }
                iN2 = aVarC.n(descriptor2, 1);
                i |= 2;
            }
        }
        aVarC.b(descriptor2);
        return new FillInTheBlankKeyphraseLocation(i, iN, iN2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FillInTheBlankKeyphraseLocation value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.l(0, value.a, descriptor2);
        bVarC.l(1, value.b, descriptor2);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
