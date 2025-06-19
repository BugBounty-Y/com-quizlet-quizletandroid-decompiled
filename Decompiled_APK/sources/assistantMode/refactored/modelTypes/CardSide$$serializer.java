package assistantMode.refactored.modelTypes;

import assistantMode.enums.l;
import assistantMode.enums.m;
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
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class CardSide$$serializer implements D {

    @NotNull
    public static final CardSide$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        CardSide$$serializer cardSide$$serializer = new CardSide$$serializer();
        INSTANCE = cardSide$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.modelTypes.CardSide", cardSide$$serializer, 4);
        pluginGeneratedSerialDescriptor.k("sideId", false);
        pluginGeneratedSerialDescriptor.k("label", false);
        pluginGeneratedSerialDescriptor.k("media", false);
        pluginGeneratedSerialDescriptor.k("distractors", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private CardSide$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = CardSide.e;
        return new KSerializer[]{P.a, l.f, kSerializerArr[2], R1.e(kSerializerArr[3])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public CardSide deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = CardSide.e;
        int i = 0;
        long j = 0;
        m mVar = null;
        List list = null;
        List list2 = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                j = aVarC.j(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                mVar = (m) aVarC.z(descriptor2, 1, l.f, mVar);
                i |= 2;
            } else if (iT == 2) {
                list = (List) aVarC.z(descriptor2, 2, kSerializerArr[2], list);
                i |= 4;
            } else {
                if (iT != 3) {
                    throw new UnknownFieldException(iT);
                }
                list2 = (List) aVarC.v(descriptor2, 3, kSerializerArr[3], list2);
                i |= 8;
            }
        }
        aVarC.b(descriptor2);
        return new CardSide(i, j, mVar, list, list2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull CardSide value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.a);
        bVarC.i(descriptor2, 1, l.f, value.b);
        KSerializer[] kSerializerArr = CardSide.e;
        bVarC.i(descriptor2, 2, kSerializerArr[2], value.c);
        boolean zD = bVarC.D(descriptor2);
        List list = value.d;
        if (zD || list != null) {
            bVarC.s(descriptor2, 3, kSerializerArr[3], list);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
