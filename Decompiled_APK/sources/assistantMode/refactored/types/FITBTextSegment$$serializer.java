package assistantMode.refactored.types;

import assistantMode.types.unions.TextAttribute;
import assistantMode.types.unions.TextAttribute$$serializer;
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
public final class FITBTextSegment$$serializer implements D {

    @NotNull
    public static final FITBTextSegment$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FITBTextSegment$$serializer fITBTextSegment$$serializer = new FITBTextSegment$$serializer();
        INSTANCE = fITBTextSegment$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FITBTextSegment", fITBTextSegment$$serializer, 1);
        pluginGeneratedSerialDescriptor.k("text", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FITBTextSegment$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{TextAttribute$$serializer.INSTANCE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FITBTextSegment deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        TextAttribute textAttribute = null;
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
                textAttribute = (TextAttribute) aVarC.z(descriptor2, 0, TextAttribute$$serializer.INSTANCE, textAttribute);
                i = 1;
            }
        }
        aVarC.b(descriptor2);
        return new FITBTextSegment(i, textAttribute);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FITBTextSegment value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, TextAttribute$$serializer.INSTANCE, value.a);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
