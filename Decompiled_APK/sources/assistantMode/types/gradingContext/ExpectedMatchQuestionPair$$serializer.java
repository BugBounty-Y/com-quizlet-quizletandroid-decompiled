package assistantMode.types.gradingContext;

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
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class ExpectedMatchQuestionPair$$serializer implements D {

    @NotNull
    public static final ExpectedMatchQuestionPair$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        ExpectedMatchQuestionPair$$serializer expectedMatchQuestionPair$$serializer = new ExpectedMatchQuestionPair$$serializer();
        INSTANCE = expectedMatchQuestionPair$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("ExpectedMatchQuestionPair", expectedMatchQuestionPair$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("promptIndex", false);
        pluginGeneratedSerialDescriptor.k("optionIndex", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private ExpectedMatchQuestionPair$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        P p = P.a;
        return new KSerializer[]{p, p};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public ExpectedMatchQuestionPair deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        long j = 0;
        long j2 = 0;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                j = aVarC.j(descriptor2, 0);
                i |= 1;
            } else {
                if (iT != 1) {
                    throw new UnknownFieldException(iT);
                }
                j2 = aVarC.j(descriptor2, 1);
                i |= 2;
            }
        }
        aVarC.b(descriptor2);
        return new ExpectedMatchQuestionPair(j, j2, i);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull ExpectedMatchQuestionPair value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.a);
        bVarC.C(descriptor2, 1, value.b);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
