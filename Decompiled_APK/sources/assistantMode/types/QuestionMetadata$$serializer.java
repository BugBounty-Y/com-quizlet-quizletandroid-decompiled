package assistantMode.types;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import java.util.List;
import java.util.Map;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class QuestionMetadata$$serializer implements kotlinx.serialization.internal.D {

    @NotNull
    public static final QuestionMetadata$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        QuestionMetadata$$serializer questionMetadata$$serializer = new QuestionMetadata$$serializer();
        INSTANCE = questionMetadata$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("QuestionMetadata", questionMetadata$$serializer, 8);
        pluginGeneratedSerialDescriptor.k("studiableItemId", false);
        pluginGeneratedSerialDescriptor.k("promptSide", false);
        pluginGeneratedSerialDescriptor.k("answerSide", false);
        pluginGeneratedSerialDescriptor.k("optionGenerationSource", true);
        pluginGeneratedSerialDescriptor.k("questionScoringInferenceMetadata", true);
        pluginGeneratedSerialDescriptor.k("questionStudiableMetadata", true);
        pluginGeneratedSerialDescriptor.k("studiableMetadataVersions", true);
        pluginGeneratedSerialDescriptor.k("meteringData", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private QuestionMetadata$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = QuestionMetadata.i;
        KSerializer kSerializerE = R1.e(P.a);
        assistantMode.enums.l lVar = assistantMode.enums.l.f;
        return new KSerializer[]{kSerializerE, R1.e(lVar), R1.e(lVar), R1.e(kSerializerArr[3]), R1.e(QuestionScoringInferenceMetadata$$serializer.INSTANCE), R1.e(QuestionStudiableMetadata$$serializer.INSTANCE), R1.e(kSerializerArr[6]), R1.e(kSerializerArr[7])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public QuestionMetadata deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = QuestionMetadata.i;
        Long l = null;
        assistantMode.enums.m mVar = null;
        assistantMode.enums.m mVar2 = null;
        List list = null;
        QuestionScoringInferenceMetadata questionScoringInferenceMetadata = null;
        QuestionStudiableMetadata questionStudiableMetadata = null;
        Map map = null;
        Map map2 = null;
        int i = 0;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    l = (Long) aVarC.v(descriptor2, 0, P.a, l);
                    i |= 1;
                    break;
                case 1:
                    mVar = (assistantMode.enums.m) aVarC.v(descriptor2, 1, assistantMode.enums.l.f, mVar);
                    i |= 2;
                    break;
                case 2:
                    mVar2 = (assistantMode.enums.m) aVarC.v(descriptor2, 2, assistantMode.enums.l.f, mVar2);
                    i |= 4;
                    break;
                case 3:
                    list = (List) aVarC.v(descriptor2, 3, kSerializerArr[3], list);
                    i |= 8;
                    break;
                case 4:
                    questionScoringInferenceMetadata = (QuestionScoringInferenceMetadata) aVarC.v(descriptor2, 4, QuestionScoringInferenceMetadata$$serializer.INSTANCE, questionScoringInferenceMetadata);
                    i |= 16;
                    break;
                case 5:
                    questionStudiableMetadata = (QuestionStudiableMetadata) aVarC.v(descriptor2, 5, QuestionStudiableMetadata$$serializer.INSTANCE, questionStudiableMetadata);
                    i |= 32;
                    break;
                case 6:
                    map = (Map) aVarC.v(descriptor2, 6, kSerializerArr[6], map);
                    i |= 64;
                    break;
                case 7:
                    map2 = (Map) aVarC.v(descriptor2, 7, kSerializerArr[7], map2);
                    i |= 128;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new QuestionMetadata(i, l, mVar, mVar2, list, questionScoringInferenceMetadata, questionStudiableMetadata, map, map2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0068  */
    @Override // kotlinx.serialization.KSerializer
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void serialize(@org.jetbrains.annotations.NotNull kotlinx.serialization.encoding.Encoder r11, @org.jetbrains.annotations.NotNull assistantMode.types.QuestionMetadata r12) {
        /*
            r10 = this;
            java.lang.String r0 = "encoder"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r11, r0)
            java.lang.String r0 = "value"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r12, r0)
            kotlinx.serialization.descriptors.SerialDescriptor r0 = r10.getDescriptor()
            kotlinx.serialization.encoding.b r11 = r11.c(r0)
            assistantMode.types.QuestionMetadata$Companion r1 = assistantMode.types.QuestionMetadata.Companion
            kotlinx.serialization.internal.P r1 = kotlinx.serialization.internal.P.a
            java.lang.Long r2 = r12.a
            r3 = 0
            r11.s(r0, r3, r1, r2)
            assistantMode.enums.l r1 = assistantMode.enums.l.f
            assistantMode.enums.m r2 = r12.b
            r3 = 1
            r11.s(r0, r3, r1, r2)
            r2 = 2
            assistantMode.enums.m r3 = r12.c
            r11.s(r0, r2, r1, r3)
            boolean r1 = r11.D(r0)
            kotlinx.serialization.KSerializer[] r2 = assistantMode.types.QuestionMetadata.i
            java.util.List r3 = r12.d
            if (r1 == 0) goto L35
            goto L37
        L35:
            if (r3 == 0) goto L3d
        L37:
            r1 = 3
            r4 = r2[r1]
            r11.s(r0, r1, r4, r3)
        L3d:
            boolean r1 = r11.D(r0)
            assistantMode.types.QuestionScoringInferenceMetadata r3 = r12.e
            if (r1 == 0) goto L46
            goto L48
        L46:
            if (r3 == 0) goto L4e
        L48:
            assistantMode.types.QuestionScoringInferenceMetadata$$serializer r1 = assistantMode.types.QuestionScoringInferenceMetadata$$serializer.INSTANCE
            r4 = 4
            r11.s(r0, r4, r1, r3)
        L4e:
            boolean r1 = r11.D(r0)
            assistantMode.types.QuestionStudiableMetadata r3 = r12.f
            if (r1 == 0) goto L57
            goto L68
        L57:
            kotlin.collections.K r5 = kotlin.collections.K.a
            assistantMode.types.QuestionStudiableMetadata r4 = new assistantMode.types.QuestionStudiableMetadata
            r6 = r5
            r7 = r5
            r8 = r5
            r9 = r5
            r4.<init>(r5, r6, r7, r8, r9)
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r3, r4)
            if (r1 != 0) goto L6e
        L68:
            assistantMode.types.QuestionStudiableMetadata$$serializer r1 = assistantMode.types.QuestionStudiableMetadata$$serializer.INSTANCE
            r4 = 5
            r11.s(r0, r4, r1, r3)
        L6e:
            boolean r1 = r11.D(r0)
            java.util.Map r3 = r12.g
            if (r1 == 0) goto L77
            goto L79
        L77:
            if (r3 == 0) goto L7f
        L79:
            r1 = 6
            r4 = r2[r1]
            r11.s(r0, r1, r4, r3)
        L7f:
            boolean r1 = r11.D(r0)
            if (r1 == 0) goto L86
            goto L8a
        L86:
            java.util.Map r1 = r12.h
            if (r1 == 0) goto L92
        L8a:
            r1 = 7
            r2 = r2[r1]
            java.util.Map r12 = r12.h
            r11.s(r0, r1, r2, r12)
        L92:
            r11.b(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.types.QuestionMetadata$$serializer.serialize(kotlinx.serialization.encoding.Encoder, assistantMode.types.QuestionMetadata):void");
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
