package assistantMode.types;

import assistantMode.types.TestGeneratorOutputMetadata;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import java.util.Map;
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
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class TestGeneratorOutputMetadata$$serializer implements kotlinx.serialization.internal.D {

    @NotNull
    public static final TestGeneratorOutputMetadata$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        TestGeneratorOutputMetadata$$serializer testGeneratorOutputMetadata$$serializer = new TestGeneratorOutputMetadata$$serializer();
        INSTANCE = testGeneratorOutputMetadata$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("TestGeneratorOutputMetadata", testGeneratorOutputMetadata$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("isRetriedTest", true);
        pluginGeneratedSerialDescriptor.k("shouldPaywallRetriedTest", true);
        pluginGeneratedSerialDescriptor.k("meteringData", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private TestGeneratorOutputMetadata$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer kSerializerE = R1.e(TestGeneratorOutputMetadata.d[2]);
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{c5053g, c5053g, kSerializerE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public TestGeneratorOutputMetadata deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = TestGeneratorOutputMetadata.d;
        Map map = null;
        boolean z = true;
        int i = 0;
        boolean zQ = false;
        boolean zQ2 = false;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                zQ = aVarC.q(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                zQ2 = aVarC.q(descriptor2, 1);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                map = (Map) aVarC.v(descriptor2, 2, kSerializerArr[2], map);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new TestGeneratorOutputMetadata(i, zQ, zQ2, map);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull TestGeneratorOutputMetadata value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        TestGeneratorOutputMetadata.Companion companion = TestGeneratorOutputMetadata.Companion;
        if (bVarC.D(descriptor2) || value.a) {
            bVarC.p(descriptor2, 0, value.a);
        }
        if (bVarC.D(descriptor2) || value.b) {
            bVarC.p(descriptor2, 1, value.b);
        }
        if (bVarC.D(descriptor2) || value.c != null) {
            bVarC.s(descriptor2, 2, TestGeneratorOutputMetadata.d[2], value.c);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
