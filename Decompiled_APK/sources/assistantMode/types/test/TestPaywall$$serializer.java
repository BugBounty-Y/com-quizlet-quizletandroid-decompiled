package assistantMode.types.test;

import assistantMode.types.TestGeneratorOutputMetadata;
import assistantMode.types.TestGeneratorOutputMetadata$$serializer;
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
public final class TestPaywall$$serializer implements D {

    @NotNull
    public static final TestPaywall$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        TestPaywall$$serializer testPaywall$$serializer = new TestPaywall$$serializer();
        INSTANCE = testPaywall$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("TestPaywall", testPaywall$$serializer, 1);
        pluginGeneratedSerialDescriptor.k("metadata", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private TestPaywall$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{TestGeneratorOutputMetadata$$serializer.INSTANCE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public TestPaywall deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        TestGeneratorOutputMetadata testGeneratorOutputMetadata = null;
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
                testGeneratorOutputMetadata = (TestGeneratorOutputMetadata) aVarC.z(descriptor2, 0, TestGeneratorOutputMetadata$$serializer.INSTANCE, testGeneratorOutputMetadata);
                i = 1;
            }
        }
        aVarC.b(descriptor2);
        return new TestPaywall(i, testGeneratorOutputMetadata);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull TestPaywall value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        if (bVarC.D(descriptor2) || !Intrinsics.b(value.a, new TestGeneratorOutputMetadata(false, 7))) {
            bVarC.i(descriptor2, 0, TestGeneratorOutputMetadata$$serializer.INSTANCE, value.a);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
