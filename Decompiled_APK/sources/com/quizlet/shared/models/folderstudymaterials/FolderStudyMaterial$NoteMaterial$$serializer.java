package com.quizlet.shared.models.folderstudymaterials;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.enums.o;
import com.quizlet.shared.enums.p;
import com.quizlet.shared.models.notes.c;
import com.quizlet.shared.models.user.User;
import com.quizlet.shared.models.user.User$$serializer;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class FolderStudyMaterial$NoteMaterial$$serializer implements D {

    @NotNull
    public static final FolderStudyMaterial$NoteMaterial$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FolderStudyMaterial$NoteMaterial$$serializer folderStudyMaterial$NoteMaterial$$serializer = new FolderStudyMaterial$NoteMaterial$$serializer();
        INSTANCE = folderStudyMaterial$NoteMaterial$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FolderStudyMaterialNoteMaterial", folderStudyMaterial$NoteMaterial$$serializer, 7);
        pluginGeneratedSerialDescriptor.k("data", false);
        pluginGeneratedSerialDescriptor.k("user", false);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("timestampSec", false);
        pluginGeneratedSerialDescriptor.k("materialId", true);
        pluginGeneratedSerialDescriptor.k("studyMaterialType", true);
        pluginGeneratedSerialDescriptor.k("name", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FolderStudyMaterial$NoteMaterial$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer kSerializer = FolderStudyMaterial$NoteMaterial.i[0];
        q0 q0Var = q0.a;
        KSerializer kSerializerE = R1.e(q0Var);
        P p = P.a;
        return new KSerializer[]{kSerializer, User$$serializer.INSTANCE, p, p, q0Var, o.f, kSerializerE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FolderStudyMaterial$NoteMaterial deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = FolderStudyMaterial$NoteMaterial.i;
        p pVar = null;
        c cVar = null;
        User user = null;
        String strR = null;
        long j = 0;
        long j2 = 0;
        int i = 0;
        boolean z = true;
        String str = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    cVar = (c) aVarC.z(descriptor2, 0, kSerializerArr[0], cVar);
                    i |= 1;
                    break;
                case 1:
                    user = (User) aVarC.z(descriptor2, 1, User$$serializer.INSTANCE, user);
                    i |= 2;
                    break;
                case 2:
                    j = aVarC.j(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    j2 = aVarC.j(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    strR = aVarC.r(descriptor2, 4);
                    i |= 16;
                    break;
                case 5:
                    pVar = (p) aVarC.z(descriptor2, 5, o.f, pVar);
                    i |= 32;
                    break;
                case 6:
                    str = (String) aVarC.v(descriptor2, 6, q0.a, str);
                    i |= 64;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new FolderStudyMaterial$NoteMaterial(i, cVar, user, j, j2, strR, pVar, str);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0075  */
    @Override // kotlinx.serialization.KSerializer
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void serialize(@org.jetbrains.annotations.NotNull kotlinx.serialization.encoding.Encoder r6, @org.jetbrains.annotations.NotNull com.quizlet.shared.models.folderstudymaterials.FolderStudyMaterial$NoteMaterial r7) {
        /*
            r5 = this;
            java.lang.String r0 = "encoder"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            java.lang.String r0 = "value"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r0)
            kotlinx.serialization.descriptors.SerialDescriptor r0 = r5.getDescriptor()
            kotlinx.serialization.encoding.b r6 = r6.c(r0)
            kotlinx.serialization.KSerializer[] r1 = com.quizlet.shared.models.folderstudymaterials.FolderStudyMaterial$NoteMaterial.i
            r2 = 0
            r1 = r1[r2]
            com.quizlet.shared.models.notes.c r3 = r7.b
            r6.i(r0, r2, r1, r3)
            com.quizlet.shared.models.user.User$$serializer r1 = com.quizlet.shared.models.user.User$$serializer.INSTANCE
            com.quizlet.shared.models.user.User r2 = r7.c
            r3 = 1
            r6.i(r0, r3, r1, r2)
            r1 = 2
            long r2 = r7.d
            r6.C(r0, r1, r2)
            r1 = 3
            long r2 = r7.e
            r6.C(r0, r1, r2)
            boolean r1 = r6.D(r0)
            com.quizlet.shared.models.notes.c r2 = r7.b
            java.lang.String r3 = r7.f
            if (r1 == 0) goto L3b
            goto L45
        L3b:
            java.lang.String r1 = r2.b()
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r3, r1)
            if (r1 != 0) goto L49
        L45:
            r1 = 4
            r6.r(r0, r1, r3)
        L49:
            boolean r1 = r6.D(r0)
            com.quizlet.shared.enums.p r3 = r7.g
            if (r1 == 0) goto L52
            goto L56
        L52:
            com.quizlet.shared.enums.p r1 = com.quizlet.shared.enums.p.g
            if (r3 == r1) goto L5c
        L56:
            com.quizlet.shared.enums.o r1 = com.quizlet.shared.enums.o.f
            r4 = 5
            r6.i(r0, r4, r1, r3)
        L5c:
            boolean r1 = r6.D(r0)
            java.lang.String r7 = r7.h
            if (r1 == 0) goto L65
            goto L75
        L65:
            com.quizlet.shared.models.notes.StudyNoteArtifactInfo$Title r1 = r2.getTitle()
            if (r1 == 0) goto L6e
            java.lang.String r1 = r1.e
            goto L6f
        L6e:
            r1 = 0
        L6f:
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r7, r1)
            if (r1 != 0) goto L7b
        L75:
            kotlinx.serialization.internal.q0 r1 = kotlinx.serialization.internal.q0.a
            r2 = 6
            r6.s(r0, r2, r1, r7)
        L7b:
            r6.b(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.models.folderstudymaterials.FolderStudyMaterial$NoteMaterial$$serializer.serialize(kotlinx.serialization.encoding.Encoder, com.quizlet.shared.models.folderstudymaterials.FolderStudyMaterial$NoteMaterial):void");
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
