package assistantMode.types.test;

import assistantMode.types.TestGeneratorOutputMetadata;
import assistantMode.types.TestGeneratorOutputMetadata$$serializer;
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
import kotlinx.serialization.internal.C5067v;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class GradedTestResult$$serializer implements D {

    @NotNull
    public static final GradedTestResult$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        GradedTestResult$$serializer gradedTestResult$$serializer = new GradedTestResult$$serializer();
        INSTANCE = gradedTestResult$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("GradedTestResult", gradedTestResult$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("gradePercentage", false);
        pluginGeneratedSerialDescriptor.k("gradedAnswers", false);
        pluginGeneratedSerialDescriptor.k("metadata", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private GradedTestResult$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{C5067v.a, GradedTestResult.d[1], TestGeneratorOutputMetadata$$serializer.INSTANCE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public GradedTestResult deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = GradedTestResult.d;
        int i = 0;
        double dY = 0.0d;
        List list = null;
        TestGeneratorOutputMetadata testGeneratorOutputMetadata = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                dY = aVarC.y(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                list = (List) aVarC.z(descriptor2, 1, kSerializerArr[1], list);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                testGeneratorOutputMetadata = (TestGeneratorOutputMetadata) aVarC.z(descriptor2, 2, TestGeneratorOutputMetadata$$serializer.INSTANCE, testGeneratorOutputMetadata);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new GradedTestResult(i, dY, list, testGeneratorOutputMetadata);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull GradedTestResult value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.A(descriptor2, 0, value.a);
        bVarC.i(descriptor2, 1, GradedTestResult.d[1], value.b);
        boolean zD = bVarC.D(descriptor2);
        TestGeneratorOutputMetadata testGeneratorOutputMetadata = value.c;
        if (zD || !Intrinsics.b(testGeneratorOutputMetadata, new TestGeneratorOutputMetadata(false, 7))) {
            bVarC.i(descriptor2, 2, TestGeneratorOutputMetadata$$serializer.INSTANCE, testGeneratorOutputMetadata);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
