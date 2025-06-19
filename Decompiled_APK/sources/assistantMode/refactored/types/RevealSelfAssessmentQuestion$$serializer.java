package assistantMode.refactored.types;

import assistantMode.enums.j;
import assistantMode.enums.k;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionElement$$serializer;
import assistantMode.types.QuestionMetadata;
import assistantMode.types.QuestionMetadata$$serializer;
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
public final class RevealSelfAssessmentQuestion$$serializer implements D {

    @NotNull
    public static final RevealSelfAssessmentQuestion$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RevealSelfAssessmentQuestion$$serializer revealSelfAssessmentQuestion$$serializer = new RevealSelfAssessmentQuestion$$serializer();
        INSTANCE = revealSelfAssessmentQuestion$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("RevealSelfAssessmentQuestion", revealSelfAssessmentQuestion$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("front", false);
        pluginGeneratedSerialDescriptor.k("back", false);
        pluginGeneratedSerialDescriptor.k("hint", false);
        pluginGeneratedSerialDescriptor.k("metadata", false);
        pluginGeneratedSerialDescriptor.k("questionType", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RevealSelfAssessmentQuestion$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        QuestionElement$$serializer questionElement$$serializer = QuestionElement$$serializer.INSTANCE;
        return new KSerializer[]{questionElement$$serializer, questionElement$$serializer, R1.e(questionElement$$serializer), QuestionMetadata$$serializer.INSTANCE, j.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RevealSelfAssessmentQuestion deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        QuestionElement questionElement = null;
        QuestionElement questionElement2 = null;
        QuestionElement questionElement3 = null;
        QuestionMetadata questionMetadata = null;
        k kVar = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                questionElement = (QuestionElement) aVarC.z(descriptor2, 0, QuestionElement$$serializer.INSTANCE, questionElement);
                i |= 1;
            } else if (iT == 1) {
                questionElement2 = (QuestionElement) aVarC.z(descriptor2, 1, QuestionElement$$serializer.INSTANCE, questionElement2);
                i |= 2;
            } else if (iT == 2) {
                questionElement3 = (QuestionElement) aVarC.v(descriptor2, 2, QuestionElement$$serializer.INSTANCE, questionElement3);
                i |= 4;
            } else if (iT == 3) {
                questionMetadata = (QuestionMetadata) aVarC.z(descriptor2, 3, QuestionMetadata$$serializer.INSTANCE, questionMetadata);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                kVar = (k) aVarC.z(descriptor2, 4, j.f, kVar);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new RevealSelfAssessmentQuestion(i, questionElement, questionElement2, questionElement3, questionMetadata, kVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RevealSelfAssessmentQuestion value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        QuestionElement$$serializer questionElement$$serializer = QuestionElement$$serializer.INSTANCE;
        bVarC.i(descriptor2, 0, questionElement$$serializer, value.a);
        bVarC.i(descriptor2, 1, questionElement$$serializer, value.b);
        bVarC.s(descriptor2, 2, questionElement$$serializer, value.c);
        bVarC.i(descriptor2, 3, QuestionMetadata$$serializer.INSTANCE, value.d);
        boolean zD = bVarC.D(descriptor2);
        k kVar = value.e;
        if (zD || kVar != k.f) {
            bVarC.i(descriptor2, 4, j.f, kVar);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
