package assistantMode.types;

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
public final class Feedback$$serializer implements kotlinx.serialization.internal.D {

    @NotNull
    public static final Feedback$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        Feedback$$serializer feedback$$serializer = new Feedback$$serializer();
        INSTANCE = feedback$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.types.Feedback", feedback$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("submittedAnswer", false);
        pluginGeneratedSerialDescriptor.k("expectedAnswer", false);
        pluginGeneratedSerialDescriptor.k("expectedAnswerDescription", false);
        pluginGeneratedSerialDescriptor.k("explanations", true);
        pluginGeneratedSerialDescriptor.k("isCompleteAnswer", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private Feedback$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = Feedback.f;
        return new KSerializer[]{R1.e(kSerializerArr[0]), kSerializerArr[1], R1.e(QuestionElement$$serializer.INSTANCE), R1.e(kSerializerArr[3]), R1.e(C5053g.a)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public Feedback deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = Feedback.f;
        int i = 0;
        v vVar = null;
        v vVar2 = null;
        QuestionElement questionElement = null;
        Map map = null;
        Boolean bool = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                vVar = (v) aVarC.v(descriptor2, 0, kSerializerArr[0], vVar);
                i |= 1;
            } else if (iT == 1) {
                vVar2 = (v) aVarC.z(descriptor2, 1, kSerializerArr[1], vVar2);
                i |= 2;
            } else if (iT == 2) {
                questionElement = (QuestionElement) aVarC.v(descriptor2, 2, QuestionElement$$serializer.INSTANCE, questionElement);
                i |= 4;
            } else if (iT == 3) {
                map = (Map) aVarC.v(descriptor2, 3, kSerializerArr[3], map);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                bool = (Boolean) aVarC.v(descriptor2, 4, C5053g.a, bool);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new Feedback(i, vVar, vVar2, questionElement, map, bool);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull Feedback value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        KSerializer[] kSerializerArr = Feedback.f;
        bVarC.s(descriptor2, 0, kSerializerArr[0], value.a);
        bVarC.i(descriptor2, 1, kSerializerArr[1], value.b);
        bVarC.s(descriptor2, 2, QuestionElement$$serializer.INSTANCE, value.c);
        boolean zD = bVarC.D(descriptor2);
        Map map = value.d;
        if (zD || map != null) {
            bVarC.s(descriptor2, 3, kSerializerArr[3], map);
        }
        boolean zD2 = bVarC.D(descriptor2);
        Boolean bool = value.e;
        if (zD2 || bool != null) {
            bVarC.s(descriptor2, 4, C5053g.a, bool);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
