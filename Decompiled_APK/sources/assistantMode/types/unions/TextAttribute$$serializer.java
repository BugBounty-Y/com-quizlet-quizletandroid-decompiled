package assistantMode.types.unions;

import assistantMode.refactored.enums.g;
import assistantMode.refactored.enums.h;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class TextAttribute$$serializer implements D {

    @NotNull
    public static final TextAttribute$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        TextAttribute$$serializer textAttribute$$serializer = new TextAttribute$$serializer();
        INSTANCE = textAttribute$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("TextAttribute", textAttribute$$serializer, 4);
        pluginGeneratedSerialDescriptor.k("plainText", false);
        pluginGeneratedSerialDescriptor.k("languageCode", false);
        pluginGeneratedSerialDescriptor.k("richText", true);
        pluginGeneratedSerialDescriptor.k("mediaType", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private TextAttribute$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer kSerializerE = R1.e(TextAttribute.e[2]);
        q0 q0Var = q0.a;
        return new KSerializer[]{q0Var, q0Var, kSerializerE, g.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public TextAttribute deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = TextAttribute.e;
        int i = 0;
        String strR = null;
        String strR2 = null;
        String str = null;
        h hVar = null;
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
                str = (String) aVarC.v(descriptor2, 2, kSerializerArr[2], str);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                hVar = (h) aVarC.z(descriptor2, 3, g.f, hVar);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new TextAttribute(i, strR, strR2, str, hVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull TextAttribute value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.a);
        bVarC.r(descriptor2, 1, value.b);
        boolean zD = bVarC.D(descriptor2);
        String str = value.c;
        if (zD || str != null) {
            bVarC.s(descriptor2, 2, TextAttribute.e[2], str);
        }
        boolean zD2 = bVarC.D(descriptor2);
        h hVar = value.d;
        if (zD2 || hVar != h.b) {
            bVarC.i(descriptor2, 3, g.f, hVar);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
