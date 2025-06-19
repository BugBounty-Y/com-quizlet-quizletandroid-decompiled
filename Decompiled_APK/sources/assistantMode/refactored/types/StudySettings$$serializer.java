package assistantMode.refactored.types;

import assistantMode.enums.B;
import assistantMode.enums.C;
import assistantMode.enums.v;
import assistantMode.enums.w;
import assistantMode.enums.x;
import assistantMode.enums.y;
import assistantMode.refactored.types.StudySettings;
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
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class StudySettings$$serializer implements D {

    @NotNull
    public static final StudySettings$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        StudySettings$$serializer studySettings$$serializer = new StudySettings$$serializer();
        INSTANCE = studySettings$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.StudySettings", studySettings$$serializer, 6);
        pluginGeneratedSerialDescriptor.k("knowledgeLevel", false);
        pluginGeneratedSerialDescriptor.k("nSidedCardSettings", false);
        pluginGeneratedSerialDescriptor.k("shuffle", false);
        pluginGeneratedSerialDescriptor.k("studyPathGoal", false);
        pluginGeneratedSerialDescriptor.k("taskSequence", false);
        pluginGeneratedSerialDescriptor.k("userLanguageCode", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private StudySettings$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{R1.e(x.f), StudySettings$NSidedCardSettings$$serializer.INSTANCE, C5053g.a, R1.e(v.f), R1.e(B.f), q0.a};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public StudySettings deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        boolean zQ = false;
        y yVar = null;
        StudySettings.NSidedCardSettings nSidedCardSettings = null;
        w wVar = null;
        C c = null;
        String strR = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    yVar = (y) aVarC.v(descriptor2, 0, x.f, yVar);
                    i |= 1;
                    break;
                case 1:
                    nSidedCardSettings = (StudySettings.NSidedCardSettings) aVarC.z(descriptor2, 1, StudySettings$NSidedCardSettings$$serializer.INSTANCE, nSidedCardSettings);
                    i |= 2;
                    break;
                case 2:
                    zQ = aVarC.q(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    wVar = (w) aVarC.v(descriptor2, 3, v.f, wVar);
                    i |= 8;
                    break;
                case 4:
                    c = (C) aVarC.v(descriptor2, 4, B.f, c);
                    i |= 16;
                    break;
                case 5:
                    strR = aVarC.r(descriptor2, 5);
                    i |= 32;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new StudySettings(i, yVar, nSidedCardSettings, zQ, wVar, c, strR);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull StudySettings value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.s(descriptor2, 0, x.f, value.a);
        bVarC.i(descriptor2, 1, StudySettings$NSidedCardSettings$$serializer.INSTANCE, value.b);
        bVarC.p(descriptor2, 2, value.c);
        bVarC.s(descriptor2, 3, v.f, value.d);
        bVarC.s(descriptor2, 4, B.f, value.e);
        bVarC.r(descriptor2, 5, value.f);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
