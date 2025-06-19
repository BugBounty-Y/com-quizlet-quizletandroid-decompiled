package com.quizlet.shared.models.api.srs;

import assistantMode.enums.l;
import assistantMode.refactored.enums.i;
import assistantMode.refactored.enums.j;
import assistantMode.refactored.enums.k;
import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.enums.m;
import com.quizlet.shared.enums.n;
import java.util.List;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.encoding.a;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class StudiableItemProgress$$serializer implements D {

    @NotNull
    public static final StudiableItemProgress$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        StudiableItemProgress$$serializer studiableItemProgress$$serializer = new StudiableItemProgress$$serializer();
        INSTANCE = studiableItemProgress$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.srs.StudiableItemProgress", studiableItemProgress$$serializer, 10);
        pluginGeneratedSerialDescriptor.k("personId", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerId", false);
        pluginGeneratedSerialDescriptor.k("studiableContainerType", false);
        pluginGeneratedSerialDescriptor.k("studiableItemId", false);
        pluginGeneratedSerialDescriptor.k("studiableItemType", false);
        pluginGeneratedSerialDescriptor.k("promptSide", false);
        pluginGeneratedSerialDescriptor.k("answerSide", false);
        pluginGeneratedSerialDescriptor.k("memoryScores", false);
        pluginGeneratedSerialDescriptor.k("nextDueDate", true);
        pluginGeneratedSerialDescriptor.k("status", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private StudiableItemProgress$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = StudiableItemProgress.k;
        P p = P.a;
        KSerializer kSerializer = kSerializerArr[7];
        KSerializer kSerializerE = R1.e(p);
        l lVar = l.f;
        return new KSerializer[]{p, p, i.f, p, k.f, lVar, lVar, kSerializer, kSerializerE, m.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public StudiableItemProgress deserialize(@NotNull Decoder decoder) {
        long j;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = StudiableItemProgress.k;
        assistantMode.refactored.enums.l lVar = null;
        long j2 = 0;
        long j3 = 0;
        long j4 = 0;
        n nVar = null;
        assistantMode.enums.m mVar = null;
        assistantMode.enums.m mVar2 = null;
        List list = null;
        Long l = null;
        j jVar = null;
        int i = 0;
        boolean z = true;
        while (z) {
            KSerializer[] kSerializerArr2 = kSerializerArr;
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    j = j2;
                    z = false;
                    kSerializerArr = kSerializerArr2;
                    j2 = j;
                case 0:
                    j = aVarC.j(descriptor2, 0);
                    i |= 1;
                    kSerializerArr = kSerializerArr2;
                    j2 = j;
                case 1:
                    j3 = aVarC.j(descriptor2, 1);
                    i |= 2;
                    kSerializerArr = kSerializerArr2;
                case 2:
                    j = j2;
                    jVar = (j) aVarC.z(descriptor2, 2, i.f, jVar);
                    i |= 4;
                    kSerializerArr = kSerializerArr2;
                    j2 = j;
                case 3:
                    j4 = aVarC.j(descriptor2, 3);
                    i |= 8;
                    kSerializerArr = kSerializerArr2;
                case 4:
                    j = j2;
                    lVar = (assistantMode.refactored.enums.l) aVarC.z(descriptor2, 4, k.f, lVar);
                    i |= 16;
                    kSerializerArr = kSerializerArr2;
                    j2 = j;
                case 5:
                    j = j2;
                    mVar = (assistantMode.enums.m) aVarC.z(descriptor2, 5, l.f, mVar);
                    i |= 32;
                    kSerializerArr = kSerializerArr2;
                    j2 = j;
                case 6:
                    j = j2;
                    mVar2 = (assistantMode.enums.m) aVarC.z(descriptor2, 6, l.f, mVar2);
                    i |= 64;
                    kSerializerArr = kSerializerArr2;
                    j2 = j;
                case 7:
                    j = j2;
                    list = (List) aVarC.z(descriptor2, 7, kSerializerArr2[7], list);
                    i |= 128;
                    kSerializerArr = kSerializerArr2;
                    j2 = j;
                case 8:
                    j = j2;
                    l = (Long) aVarC.v(descriptor2, 8, P.a, l);
                    i |= 256;
                    kSerializerArr = kSerializerArr2;
                    j2 = j;
                case 9:
                    j = j2;
                    nVar = (n) aVarC.z(descriptor2, 9, m.f, nVar);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    kSerializerArr = kSerializerArr2;
                    j2 = j;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new StudiableItemProgress(i, j2, j3, jVar, j4, lVar, mVar, mVar2, list, l, nVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull StudiableItemProgress value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.a);
        bVarC.C(descriptor2, 1, value.b);
        bVarC.i(descriptor2, 2, i.f, value.c);
        bVarC.C(descriptor2, 3, value.d);
        bVarC.i(descriptor2, 4, k.f, value.e);
        l lVar = l.f;
        bVarC.i(descriptor2, 5, lVar, value.f);
        bVarC.i(descriptor2, 6, lVar, value.g);
        bVarC.i(descriptor2, 7, StudiableItemProgress.k[7], value.h);
        boolean zD = bVarC.D(descriptor2);
        Long l = value.i;
        if (zD || l != null) {
            bVarC.s(descriptor2, 8, P.a, l);
        }
        bVarC.i(descriptor2, 9, m.f, value.j);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
