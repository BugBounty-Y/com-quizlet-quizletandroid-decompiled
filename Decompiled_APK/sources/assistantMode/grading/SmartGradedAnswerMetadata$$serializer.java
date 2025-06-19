package assistantMode.grading;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.models.api.grading.LongtextGradingResult;
import com.quizlet.shared.models.api.grading.LongtextGradingResult$$serializer;
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
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class SmartGradedAnswerMetadata$$serializer implements D {

    @NotNull
    public static final SmartGradedAnswerMetadata$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        SmartGradedAnswerMetadata$$serializer smartGradedAnswerMetadata$$serializer = new SmartGradedAnswerMetadata$$serializer();
        INSTANCE = smartGradedAnswerMetadata$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.grading.SmartGradedAnswerMetadata", smartGradedAnswerMetadata$$serializer, 6);
        pluginGeneratedSerialDescriptor.k("longtextGradingResult", false);
        pluginGeneratedSerialDescriptor.k("wasRequestSuccess", false);
        pluginGeneratedSerialDescriptor.k("logStartTimestamp", false);
        pluginGeneratedSerialDescriptor.k("logEndTimestamp", false);
        pluginGeneratedSerialDescriptor.k("logGradedResultTimestamp", true);
        pluginGeneratedSerialDescriptor.k("wasSmartGradingUsed", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private SmartGradedAnswerMetadata$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer kSerializerE = R1.e(LongtextGradingResult$$serializer.INSTANCE);
        P p = P.a;
        KSerializer kSerializerE2 = R1.e(p);
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{kSerializerE, c5053g, p, p, kSerializerE2, c5053g};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SmartGradedAnswerMetadata deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        boolean zQ = false;
        boolean zQ2 = false;
        LongtextGradingResult longtextGradingResult = null;
        Long l = null;
        long j = 0;
        long j2 = 0;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    longtextGradingResult = (LongtextGradingResult) aVarC.v(descriptor2, 0, LongtextGradingResult$$serializer.INSTANCE, longtextGradingResult);
                    i |= 1;
                    break;
                case 1:
                    zQ = aVarC.q(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    j = aVarC.j(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    j2 = aVarC.j(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    l = (Long) aVarC.v(descriptor2, 4, P.a, l);
                    i |= 16;
                    break;
                case 5:
                    zQ2 = aVarC.q(descriptor2, 5);
                    i |= 32;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new SmartGradedAnswerMetadata(i, longtextGradingResult, zQ, j, j2, l, zQ2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull SmartGradedAnswerMetadata value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.s(descriptor2, 0, LongtextGradingResult$$serializer.INSTANCE, value.a);
        bVarC.p(descriptor2, 1, value.b);
        bVarC.C(descriptor2, 2, value.c);
        bVarC.C(descriptor2, 3, value.d);
        boolean zD = bVarC.D(descriptor2);
        Long l = value.e;
        if (zD || l != null) {
            bVarC.s(descriptor2, 4, P.a, l);
        }
        boolean zD2 = bVarC.D(descriptor2);
        boolean z = value.f;
        if (zD2 || !z) {
            bVarC.p(descriptor2, 5, z);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
