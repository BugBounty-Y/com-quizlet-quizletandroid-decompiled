package assistantMode.refactored.modelTypes;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
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
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class MultipleChoiceOption$$serializer implements D {

    @NotNull
    public static final MultipleChoiceOption$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        MultipleChoiceOption$$serializer multipleChoiceOption$$serializer = new MultipleChoiceOption$$serializer();
        INSTANCE = multipleChoiceOption$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.modelTypes.MultipleChoiceOption", multipleChoiceOption$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("optionId", false);
        pluginGeneratedSerialDescriptor.k(DBAnswerFields.Names.IS_CORRECT, false);
        pluginGeneratedSerialDescriptor.k("rank", false);
        pluginGeneratedSerialDescriptor.k("optionMedia", false);
        pluginGeneratedSerialDescriptor.k("explanationMedia", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private MultipleChoiceOption$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = MultipleChoiceOption.f;
        return new KSerializer[]{P.a, C5053g.a, R1.e(K.a), kSerializerArr[3], kSerializerArr[4]};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public MultipleChoiceOption deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = MultipleChoiceOption.f;
        int i = 0;
        boolean zQ = false;
        long j = 0;
        Integer num = null;
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
                zQ = aVarC.q(descriptor2, 1);
                i |= 2;
            } else if (iT == 2) {
                num = (Integer) aVarC.v(descriptor2, 2, K.a, num);
                i |= 4;
            } else if (iT == 3) {
                list = (List) aVarC.z(descriptor2, 3, kSerializerArr[3], list);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                list2 = (List) aVarC.z(descriptor2, 4, kSerializerArr[4], list2);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new MultipleChoiceOption(i, j, zQ, num, list, list2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull MultipleChoiceOption value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.a);
        bVarC.p(descriptor2, 1, value.b);
        bVarC.s(descriptor2, 2, K.a, value.c);
        KSerializer[] kSerializerArr = MultipleChoiceOption.f;
        bVarC.i(descriptor2, 3, kSerializerArr[3], value.d);
        bVarC.i(descriptor2, 4, kSerializerArr[4], value.e);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
