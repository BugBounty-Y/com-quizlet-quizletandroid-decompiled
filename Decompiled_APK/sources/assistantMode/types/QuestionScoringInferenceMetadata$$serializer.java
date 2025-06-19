package assistantMode.types;

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
import kotlinx.serialization.internal.C5067v;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class QuestionScoringInferenceMetadata$$serializer implements kotlinx.serialization.internal.D {

    @NotNull
    public static final QuestionScoringInferenceMetadata$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        QuestionScoringInferenceMetadata$$serializer questionScoringInferenceMetadata$$serializer = new QuestionScoringInferenceMetadata$$serializer();
        INSTANCE = questionScoringInferenceMetadata$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.types.QuestionScoringInferenceMetadata", questionScoringInferenceMetadata$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("currentScore", false);
        pluginGeneratedSerialDescriptor.k("modelVersion", false);
        pluginGeneratedSerialDescriptor.k("modelName", false);
        pluginGeneratedSerialDescriptor.k("priorityScore", true);
        pluginGeneratedSerialDescriptor.k("priorityMethod", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private QuestionScoringInferenceMetadata$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        C5067v c5067v = C5067v.a;
        q0 q0Var = q0.a;
        return new KSerializer[]{c5067v, q0Var, q0Var, R1.e(c5067v), R1.e(q0Var)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public QuestionScoringInferenceMetadata deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        double dY = 0.0d;
        String strR = null;
        String strR2 = null;
        Double d = null;
        String str = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                dY = aVarC.y(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                strR = aVarC.r(descriptor2, 1);
                i |= 2;
            } else if (iT == 2) {
                strR2 = aVarC.r(descriptor2, 2);
                i |= 4;
            } else if (iT == 3) {
                d = (Double) aVarC.v(descriptor2, 3, C5067v.a, d);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                str = (String) aVarC.v(descriptor2, 4, q0.a, str);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new QuestionScoringInferenceMetadata(i, dY, strR, strR2, d, str);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull QuestionScoringInferenceMetadata value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.A(descriptor2, 0, value.a);
        bVarC.r(descriptor2, 1, value.b);
        bVarC.r(descriptor2, 2, value.c);
        boolean zD = bVarC.D(descriptor2);
        Double d = value.d;
        if (zD || d != null) {
            bVarC.s(descriptor2, 3, C5067v.a, d);
        }
        boolean zD2 = bVarC.D(descriptor2);
        String str = value.e;
        if (zD2 || str != null) {
            bVarC.s(descriptor2, 4, q0.a, str);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
