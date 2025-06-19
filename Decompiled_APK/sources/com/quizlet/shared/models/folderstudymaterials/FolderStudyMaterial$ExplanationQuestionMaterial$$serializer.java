package com.quizlet.shared.models.folderstudymaterials;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.enums.o;
import com.quizlet.shared.enums.p;
import com.quizlet.shared.models.explanations.ExplanationQuestion;
import com.quizlet.shared.models.explanations.ExplanationQuestion$$serializer;
import com.quizlet.shared.models.folderstudymaterials.FolderStudyMaterial$ExplanationQuestionMaterial;
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
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class FolderStudyMaterial$ExplanationQuestionMaterial$$serializer implements D {

    @NotNull
    public static final FolderStudyMaterial$ExplanationQuestionMaterial$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FolderStudyMaterial$ExplanationQuestionMaterial$$serializer folderStudyMaterial$ExplanationQuestionMaterial$$serializer = new FolderStudyMaterial$ExplanationQuestionMaterial$$serializer();
        INSTANCE = folderStudyMaterial$ExplanationQuestionMaterial$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FolderStudyMaterialExplanationQuestionMaterial", folderStudyMaterial$ExplanationQuestionMaterial$$serializer, 6);
        pluginGeneratedSerialDescriptor.k("data", false);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("timestampSec", false);
        pluginGeneratedSerialDescriptor.k("materialId", true);
        pluginGeneratedSerialDescriptor.k("studyMaterialType", true);
        pluginGeneratedSerialDescriptor.k("name", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FolderStudyMaterial$ExplanationQuestionMaterial$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        KSerializer kSerializerE = R1.e(q0Var);
        P p = P.a;
        return new KSerializer[]{ExplanationQuestion$$serializer.INSTANCE, p, p, q0Var, o.f, kSerializerE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FolderStudyMaterial$ExplanationQuestionMaterial deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        String str = null;
        int i = 0;
        ExplanationQuestion explanationQuestion = null;
        String strR = null;
        p pVar = null;
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
                    explanationQuestion = (ExplanationQuestion) aVarC.z(descriptor2, 0, ExplanationQuestion$$serializer.INSTANCE, explanationQuestion);
                    i |= 1;
                    break;
                case 1:
                    j = aVarC.j(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    j2 = aVarC.j(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    strR = aVarC.r(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    pVar = (p) aVarC.z(descriptor2, 4, o.f, pVar);
                    i |= 16;
                    break;
                case 5:
                    str = (String) aVarC.v(descriptor2, 5, q0.a, str);
                    i |= 32;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new FolderStudyMaterial$ExplanationQuestionMaterial(i, explanationQuestion, j, j2, strR, pVar, str);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FolderStudyMaterial$ExplanationQuestionMaterial value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        FolderStudyMaterial$ExplanationQuestionMaterial.Companion companion = FolderStudyMaterial$ExplanationQuestionMaterial.Companion;
        bVarC.i(descriptor2, 0, ExplanationQuestion$$serializer.INSTANCE, value.b);
        bVarC.C(descriptor2, 1, value.c);
        bVarC.C(descriptor2, 2, value.d);
        boolean zD = bVarC.D(descriptor2);
        ExplanationQuestion explanationQuestion = value.b;
        String str = value.e;
        if (zD || !Intrinsics.b(str, explanationQuestion.c)) {
            bVarC.r(descriptor2, 3, str);
        }
        boolean zD2 = bVarC.D(descriptor2);
        p pVar = value.f;
        if (zD2 || pVar != p.f) {
            bVarC.i(descriptor2, 4, o.f, pVar);
        }
        boolean zD3 = bVarC.D(descriptor2);
        String str2 = value.g;
        if (zD3 || !Intrinsics.b(str2, explanationQuestion.f.b)) {
            bVarC.s(descriptor2, 5, q0.a, str2);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
