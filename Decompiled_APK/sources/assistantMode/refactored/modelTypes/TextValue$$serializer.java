package assistantMode.refactored.modelTypes;

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
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class TextValue$$serializer implements D {

    @NotNull
    public static final TextValue$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        TextValue$$serializer textValue$$serializer = new TextValue$$serializer();
        INSTANCE = textValue$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("1", textValue$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("plainText", false);
        pluginGeneratedSerialDescriptor.k("languageCode", false);
        pluginGeneratedSerialDescriptor.k("ttsUrl", false);
        pluginGeneratedSerialDescriptor.k("ttsSlowUrl", false);
        pluginGeneratedSerialDescriptor.k("richText", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private TextValue$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = TextValue.f;
        q0 q0Var = q0.a;
        return new KSerializer[]{q0Var, q0Var, R1.e(q0Var), R1.e(q0Var), R1.e(kSerializerArr[4])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public TextValue deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = TextValue.f;
        int i = 0;
        String strR = null;
        String strR2 = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                strR = aVarC.r(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                strR2 = aVarC.r(descriptor2, 1);
                i |= 2;
            } else if (iT == 2) {
                str = (String) aVarC.v(descriptor2, 2, q0.a, str);
                i |= 4;
            } else if (iT == 3) {
                str2 = (String) aVarC.v(descriptor2, 3, q0.a, str2);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                str3 = (String) aVarC.v(descriptor2, 4, kSerializerArr[4], str3);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new TextValue(i, strR, strR2, str, str2, str3);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull TextValue value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.a);
        bVarC.r(descriptor2, 1, value.b);
        q0 q0Var = q0.a;
        bVarC.s(descriptor2, 2, q0Var, value.c);
        bVarC.s(descriptor2, 3, q0Var, value.d);
        boolean zD = bVarC.D(descriptor2);
        String str = value.e;
        if (zD || str != null) {
            bVarC.s(descriptor2, 4, TextValue.f[4], str);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
