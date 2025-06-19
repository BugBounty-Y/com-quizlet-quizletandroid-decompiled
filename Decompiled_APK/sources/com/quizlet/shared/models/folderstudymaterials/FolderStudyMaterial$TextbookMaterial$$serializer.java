package com.quizlet.shared.models.folderstudymaterials;

import com.quizlet.shared.enums.o;
import com.quizlet.shared.enums.p;
import com.quizlet.shared.models.explanations.Textbook;
import com.quizlet.shared.models.explanations.Textbook$$serializer;
import com.quizlet.shared.models.folderstudymaterials.FolderStudyMaterial$TextbookMaterial;
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
public final class FolderStudyMaterial$TextbookMaterial$$serializer implements D {

    @NotNull
    public static final FolderStudyMaterial$TextbookMaterial$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FolderStudyMaterial$TextbookMaterial$$serializer folderStudyMaterial$TextbookMaterial$$serializer = new FolderStudyMaterial$TextbookMaterial$$serializer();
        INSTANCE = folderStudyMaterial$TextbookMaterial$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FolderStudyMaterialTextbookMaterial", folderStudyMaterial$TextbookMaterial$$serializer, 6);
        pluginGeneratedSerialDescriptor.k("data", false);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("timestampSec", false);
        pluginGeneratedSerialDescriptor.k("materialId", true);
        pluginGeneratedSerialDescriptor.k("studyMaterialType", true);
        pluginGeneratedSerialDescriptor.k("name", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FolderStudyMaterial$TextbookMaterial$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        P p = P.a;
        q0 q0Var = q0.a;
        return new KSerializer[]{Textbook$$serializer.INSTANCE, p, p, q0Var, o.f, q0Var};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FolderStudyMaterial$TextbookMaterial deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        Textbook textbook = null;
        String strR = null;
        p pVar = null;
        String strR2 = null;
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
                    textbook = (Textbook) aVarC.z(descriptor2, 0, Textbook$$serializer.INSTANCE, textbook);
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
                    strR2 = aVarC.r(descriptor2, 5);
                    i |= 32;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new FolderStudyMaterial$TextbookMaterial(i, textbook, j, j2, strR, pVar, strR2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FolderStudyMaterial$TextbookMaterial value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        FolderStudyMaterial$TextbookMaterial.Companion companion = FolderStudyMaterial$TextbookMaterial.Companion;
        bVarC.i(descriptor2, 0, Textbook$$serializer.INSTANCE, value.b);
        bVarC.C(descriptor2, 1, value.c);
        bVarC.C(descriptor2, 2, value.d);
        boolean zD = bVarC.D(descriptor2);
        Textbook textbook = value.b;
        String str = value.e;
        if (zD || !Intrinsics.b(str, textbook.c)) {
            bVarC.r(descriptor2, 3, str);
        }
        boolean zD2 = bVarC.D(descriptor2);
        p pVar = value.f;
        if (zD2 || pVar != p.d) {
            bVarC.i(descriptor2, 4, o.f, pVar);
        }
        boolean zD3 = bVarC.D(descriptor2);
        String str2 = value.g;
        if (zD3 || !Intrinsics.b(str2, textbook.d)) {
            bVarC.r(descriptor2, 5, str2);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
