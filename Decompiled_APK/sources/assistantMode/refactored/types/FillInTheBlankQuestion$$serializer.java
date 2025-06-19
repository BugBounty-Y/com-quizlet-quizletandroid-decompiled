package assistantMode.refactored.types;

import assistantMode.enums.j;
import assistantMode.enums.k;
import assistantMode.refactored.types.FillInTheBlankQuestion;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionElement$$serializer;
import assistantMode.types.QuestionMetadata;
import assistantMode.types.QuestionMetadata$$serializer;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
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
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class FillInTheBlankQuestion$$serializer implements D {

    @NotNull
    public static final FillInTheBlankQuestion$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FillInTheBlankQuestion$$serializer fillInTheBlankQuestion$$serializer = new FillInTheBlankQuestion$$serializer();
        INSTANCE = fillInTheBlankQuestion$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FillInTheBlankQuestion", fillInTheBlankQuestion$$serializer, 6);
        pluginGeneratedSerialDescriptor.k("prompt", false);
        pluginGeneratedSerialDescriptor.k("segments", false);
        pluginGeneratedSerialDescriptor.k("metadata", false);
        pluginGeneratedSerialDescriptor.k("modelVersion", false);
        pluginGeneratedSerialDescriptor.k("algorithm", true);
        pluginGeneratedSerialDescriptor.k("questionType", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FillInTheBlankQuestion$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer kSerializer = FillInTheBlankQuestion.g[1];
        q0 q0Var = q0.a;
        return new KSerializer[]{QuestionElement$$serializer.INSTANCE, kSerializer, QuestionMetadata$$serializer.INSTANCE, q0Var, R1.e(q0Var), j.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FillInTheBlankQuestion deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = FillInTheBlankQuestion.g;
        int i = 0;
        QuestionElement questionElement = null;
        List list = null;
        QuestionMetadata questionMetadata = null;
        String strR = null;
        String str = null;
        k kVar = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    questionElement = (QuestionElement) aVarC.z(descriptor2, 0, QuestionElement$$serializer.INSTANCE, questionElement);
                    i |= 1;
                    break;
                case 1:
                    list = (List) aVarC.z(descriptor2, 1, kSerializerArr[1], list);
                    i |= 2;
                    break;
                case 2:
                    questionMetadata = (QuestionMetadata) aVarC.z(descriptor2, 2, QuestionMetadata$$serializer.INSTANCE, questionMetadata);
                    i |= 4;
                    break;
                case 3:
                    strR = aVarC.r(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    str = (String) aVarC.v(descriptor2, 4, q0.a, str);
                    i |= 16;
                    break;
                case 5:
                    kVar = (k) aVarC.z(descriptor2, 5, j.f, kVar);
                    i |= 32;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new FillInTheBlankQuestion(i, questionElement, list, questionMetadata, strR, str, kVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FillInTheBlankQuestion value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        FillInTheBlankQuestion.Companion companion = FillInTheBlankQuestion.Companion;
        bVarC.i(descriptor2, 0, QuestionElement$$serializer.INSTANCE, value.a);
        bVarC.i(descriptor2, 1, FillInTheBlankQuestion.g[1], value.b);
        bVarC.i(descriptor2, 2, QuestionMetadata$$serializer.INSTANCE, value.c);
        bVarC.r(descriptor2, 3, value.d);
        boolean zD = bVarC.D(descriptor2);
        String str = value.e;
        if (zD || str != null) {
            bVarC.s(descriptor2, 4, q0.a, str);
        }
        boolean zD2 = bVarC.D(descriptor2);
        k kVar = value.f;
        if (zD2 || kVar != k.l) {
            bVarC.i(descriptor2, 5, j.f, kVar);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
