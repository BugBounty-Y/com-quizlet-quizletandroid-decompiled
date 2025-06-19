package assistantMode.types;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
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
public final class GradedAnswer$$serializer implements kotlinx.serialization.internal.D {

    @NotNull
    public static final GradedAnswer$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        GradedAnswer$$serializer gradedAnswer$$serializer = new GradedAnswer$$serializer();
        INSTANCE = gradedAnswer$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.types.GradedAnswer", gradedAnswer$$serializer, 4);
        pluginGeneratedSerialDescriptor.k(DBAnswerFields.Names.IS_CORRECT, false);
        pluginGeneratedSerialDescriptor.k("feedback", false);
        pluginGeneratedSerialDescriptor.k("gradingSettingsSuggestion", true);
        pluginGeneratedSerialDescriptor.k("metadata", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private GradedAnswer$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{C5053g.a, Feedback$$serializer.INSTANCE, R1.e(AssistantGradingSettingsSuggestion$$serializer.INSTANCE), GradedAnswer.e[3]};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public GradedAnswer deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = GradedAnswer.e;
        int i = 0;
        boolean zQ = false;
        Feedback feedback = null;
        AssistantGradingSettingsSuggestion assistantGradingSettingsSuggestion = null;
        assistantMode.grading.b bVar = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                zQ = aVarC.q(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                feedback = (Feedback) aVarC.z(descriptor2, 1, Feedback$$serializer.INSTANCE, feedback);
                i |= 2;
            } else if (iT == 2) {
                assistantGradingSettingsSuggestion = (AssistantGradingSettingsSuggestion) aVarC.v(descriptor2, 2, AssistantGradingSettingsSuggestion$$serializer.INSTANCE, assistantGradingSettingsSuggestion);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                bVar = (assistantMode.grading.b) aVarC.z(descriptor2, 3, kSerializerArr[3], bVar);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new GradedAnswer(i, zQ, feedback, assistantGradingSettingsSuggestion, bVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull GradedAnswer value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.p(descriptor2, 0, value.a);
        bVarC.i(descriptor2, 1, Feedback$$serializer.INSTANCE, value.b);
        boolean zD = bVarC.D(descriptor2);
        AssistantGradingSettingsSuggestion assistantGradingSettingsSuggestion = value.c;
        if (zD || assistantGradingSettingsSuggestion != null) {
            bVarC.s(descriptor2, 2, AssistantGradingSettingsSuggestion$$serializer.INSTANCE, assistantGradingSettingsSuggestion);
        }
        bVarC.i(descriptor2, 3, GradedAnswer.e[3], value.d);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
