package assistantMode.types.test;

import com.google.android.gms.ads.g;
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
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class TestSettings$$serializer implements D {

    @NotNull
    public static final TestSettings$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        TestSettings$$serializer testSettings$$serializer = new TestSettings$$serializer();
        INSTANCE = testSettings$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.types.test.TestSettings", testSettings$$serializer, 12);
        pluginGeneratedSerialDescriptor.k("enabledQuestionTypes", false);
        pluginGeneratedSerialDescriptor.k("enabledPromptSides", false);
        pluginGeneratedSerialDescriptor.k("enabledAnswerSides", false);
        pluginGeneratedSerialDescriptor.k("numQuestions", false);
        pluginGeneratedSerialDescriptor.k("includeStarredItems", true);
        pluginGeneratedSerialDescriptor.k("useMissedAndUnstudied", true);
        pluginGeneratedSerialDescriptor.k("shouldOrderTestQuestions", true);
        pluginGeneratedSerialDescriptor.k("studiableItemIds", true);
        pluginGeneratedSerialDescriptor.k("starredStudiableItemIds", true);
        pluginGeneratedSerialDescriptor.k("correctStudiableIds", true);
        pluginGeneratedSerialDescriptor.k("missedStudiableIds", true);
        pluginGeneratedSerialDescriptor.k("unstudiedItemIds", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private TestSettings$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = TestSettings.m;
        KSerializer kSerializer = kSerializerArr[0];
        KSerializer kSerializer2 = kSerializerArr[1];
        KSerializer kSerializer3 = kSerializerArr[2];
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{kSerializer, kSerializer2, kSerializer3, K.a, R1.e(c5053g), R1.e(c5053g), R1.e(c5053g), R1.e(kSerializerArr[7]), R1.e(kSerializerArr[8]), R1.e(kSerializerArr[9]), R1.e(kSerializerArr[10]), R1.e(kSerializerArr[11])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public TestSettings deserialize(@NotNull Decoder decoder) {
        KSerializer[] kSerializerArr;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr2 = TestSettings.m;
        List list = null;
        List list2 = null;
        List list3 = null;
        List list4 = null;
        List list5 = null;
        List list6 = null;
        List list7 = null;
        Boolean bool = null;
        Boolean bool2 = null;
        Boolean bool3 = null;
        List list8 = null;
        int i = 0;
        boolean z = true;
        int iN = 0;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    continue;
                case 0:
                    kSerializerArr = kSerializerArr2;
                    list4 = (List) aVarC.z(descriptor2, 0, kSerializerArr[0], list4);
                    i |= 1;
                    break;
                case 1:
                    kSerializerArr = kSerializerArr2;
                    list5 = (List) aVarC.z(descriptor2, 1, kSerializerArr[1], list5);
                    i |= 2;
                    break;
                case 2:
                    kSerializerArr = kSerializerArr2;
                    list6 = (List) aVarC.z(descriptor2, 2, kSerializerArr[2], list6);
                    i |= 4;
                    break;
                case 3:
                    kSerializerArr = kSerializerArr2;
                    iN = aVarC.n(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    kSerializerArr = kSerializerArr2;
                    bool = (Boolean) aVarC.v(descriptor2, 4, C5053g.a, bool);
                    i |= 16;
                    break;
                case 5:
                    kSerializerArr = kSerializerArr2;
                    bool2 = (Boolean) aVarC.v(descriptor2, 5, C5053g.a, bool2);
                    i |= 32;
                    break;
                case 6:
                    kSerializerArr = kSerializerArr2;
                    bool3 = (Boolean) aVarC.v(descriptor2, 6, C5053g.a, bool3);
                    i |= 64;
                    break;
                case 7:
                    kSerializerArr = kSerializerArr2;
                    list8 = (List) aVarC.v(descriptor2, 7, kSerializerArr[7], list8);
                    i |= 128;
                    break;
                case 8:
                    kSerializerArr = kSerializerArr2;
                    list = (List) aVarC.v(descriptor2, 8, kSerializerArr[8], list);
                    i |= 256;
                    break;
                case 9:
                    kSerializerArr = kSerializerArr2;
                    list2 = (List) aVarC.v(descriptor2, 9, kSerializerArr[9], list2);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    break;
                case 10:
                    kSerializerArr = kSerializerArr2;
                    list3 = (List) aVarC.v(descriptor2, 10, kSerializerArr[10], list3);
                    i |= 1024;
                    break;
                case 11:
                    kSerializerArr = kSerializerArr2;
                    list7 = (List) aVarC.v(descriptor2, 11, kSerializerArr[11], list7);
                    i |= 2048;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
            kSerializerArr2 = kSerializerArr;
        }
        aVarC.b(descriptor2);
        return new TestSettings(i, list4, list5, list6, iN, bool, bool2, bool3, list8, list, list2, list3, list7);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull TestSettings value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        KSerializer[] kSerializerArr = TestSettings.m;
        bVarC.i(descriptor2, 0, kSerializerArr[0], value.a);
        bVarC.i(descriptor2, 1, kSerializerArr[1], value.b);
        bVarC.i(descriptor2, 2, kSerializerArr[2], value.c);
        bVarC.l(3, value.d, descriptor2);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.e;
        if (zD || !Intrinsics.b(bool, Boolean.FALSE)) {
            bVarC.s(descriptor2, 4, C5053g.a, bool);
        }
        boolean zD2 = bVarC.D(descriptor2);
        Boolean bool2 = value.f;
        if (zD2 || !Intrinsics.b(bool2, Boolean.FALSE)) {
            bVarC.s(descriptor2, 5, C5053g.a, bool2);
        }
        boolean zD3 = bVarC.D(descriptor2);
        Boolean bool3 = value.g;
        if (zD3 || !Intrinsics.b(bool3, Boolean.FALSE)) {
            bVarC.s(descriptor2, 6, C5053g.a, bool3);
        }
        boolean zD4 = bVarC.D(descriptor2);
        List list = value.h;
        if (zD4 || list != null) {
            bVarC.s(descriptor2, 7, kSerializerArr[7], list);
        }
        boolean zD5 = bVarC.D(descriptor2);
        List list2 = value.i;
        if (zD5 || list2 != null) {
            bVarC.s(descriptor2, 8, kSerializerArr[8], list2);
        }
        boolean zD6 = bVarC.D(descriptor2);
        List list3 = value.j;
        if (zD6 || list3 != null) {
            bVarC.s(descriptor2, 9, kSerializerArr[9], list3);
        }
        boolean zD7 = bVarC.D(descriptor2);
        List list4 = value.k;
        if (zD7 || list4 != null) {
            bVarC.s(descriptor2, 10, kSerializerArr[10], list4);
        }
        boolean zD8 = bVarC.D(descriptor2);
        List list5 = value.l;
        if (zD8 || list5 != null) {
            bVarC.s(descriptor2, 11, kSerializerArr[11], list5);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
