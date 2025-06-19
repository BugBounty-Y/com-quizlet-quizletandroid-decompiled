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
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class AssistantGradingSettingsSuggestion$$serializer implements kotlinx.serialization.internal.D {

    @NotNull
    public static final AssistantGradingSettingsSuggestion$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        AssistantGradingSettingsSuggestion$$serializer assistantGradingSettingsSuggestion$$serializer = new AssistantGradingSettingsSuggestion$$serializer();
        INSTANCE = assistantGradingSettingsSuggestion$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.types.AssistantGradingSettingsSuggestion", assistantGradingSettingsSuggestion$$serializer, 4);
        pluginGeneratedSerialDescriptor.k("acceptsPartialAnswer", true);
        pluginGeneratedSerialDescriptor.k("acceptsAnswersWithTypos", true);
        pluginGeneratedSerialDescriptor.k("acceptsSmartGrading", true);
        pluginGeneratedSerialDescriptor.k("allowsRetry", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private AssistantGradingSettingsSuggestion$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{R1.e(c5053g), R1.e(c5053g), R1.e(c5053g), R1.e(c5053g)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public AssistantGradingSettingsSuggestion deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        Boolean bool = null;
        Boolean bool2 = null;
        Boolean bool3 = null;
        Boolean bool4 = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                bool = (Boolean) aVarC.v(descriptor2, 0, C5053g.a, bool);
                i |= 1;
            } else if (iT == 1) {
                bool2 = (Boolean) aVarC.v(descriptor2, 1, C5053g.a, bool2);
                i |= 2;
            } else if (iT == 2) {
                bool3 = (Boolean) aVarC.v(descriptor2, 2, C5053g.a, bool3);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                bool4 = (Boolean) aVarC.v(descriptor2, 3, C5053g.a, bool4);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new AssistantGradingSettingsSuggestion(i, bool, bool2, bool3, bool4);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull AssistantGradingSettingsSuggestion value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        if (bVarC.D(descriptor2) || value.a != null) {
            bVarC.s(descriptor2, 0, C5053g.a, value.a);
        }
        if (bVarC.D(descriptor2) || value.b != null) {
            bVarC.s(descriptor2, 1, C5053g.a, value.b);
        }
        if (bVarC.D(descriptor2) || value.c != null) {
            bVarC.s(descriptor2, 2, C5053g.a, value.c);
        }
        if (bVarC.D(descriptor2) || value.d != null) {
            bVarC.s(descriptor2, 3, C5053g.a, value.d);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
