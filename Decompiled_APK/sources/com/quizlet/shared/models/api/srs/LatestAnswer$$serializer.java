package com.quizlet.shared.models.api.srs;

import assistantMode.enums.C1451e;
import assistantMode.enums.EnumC1452f;
import assistantMode.enums.l;
import assistantMode.enums.m;
import assistantMode.enums.t;
import assistantMode.enums.u;
import assistantMode.refactored.enums.k;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
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
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class LatestAnswer$$serializer implements D {

    @NotNull
    public static final LatestAnswer$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        LatestAnswer$$serializer latestAnswer$$serializer = new LatestAnswer$$serializer();
        INSTANCE = latestAnswer$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.srs.LatestAnswer", latestAnswer$$serializer, 9);
        pluginGeneratedSerialDescriptor.k("studiableItemId", false);
        pluginGeneratedSerialDescriptor.k("studiableItemType", false);
        pluginGeneratedSerialDescriptor.k("studyModeType", false);
        pluginGeneratedSerialDescriptor.k("answerType", false);
        pluginGeneratedSerialDescriptor.k("questionType", true);
        pluginGeneratedSerialDescriptor.k("promptSide", false);
        pluginGeneratedSerialDescriptor.k("answerSide", false);
        pluginGeneratedSerialDescriptor.k("answerTimestamp", false);
        pluginGeneratedSerialDescriptor.k(DBAnswerFields.Names.CORRECTNESS, false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private LatestAnswer$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        K k = K.a;
        KSerializer kSerializerE = R1.e(k);
        P p = P.a;
        l lVar = l.f;
        return new KSerializer[]{p, k.f, t.f, k, kSerializerE, lVar, lVar, p, C1451e.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public LatestAnswer deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        m mVar = null;
        long j = 0;
        long j2 = 0;
        EnumC1452f enumC1452f = null;
        assistantMode.refactored.enums.l lVar = null;
        u uVar = null;
        Integer num = null;
        m mVar2 = null;
        int i = 0;
        int iN = 0;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    j = aVarC.j(descriptor2, 0);
                    i |= 1;
                    break;
                case 1:
                    lVar = (assistantMode.refactored.enums.l) aVarC.z(descriptor2, 1, k.f, lVar);
                    i |= 2;
                    break;
                case 2:
                    uVar = (u) aVarC.z(descriptor2, 2, t.f, uVar);
                    i |= 4;
                    break;
                case 3:
                    iN = aVarC.n(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    num = (Integer) aVarC.v(descriptor2, 4, K.a, num);
                    i |= 16;
                    break;
                case 5:
                    mVar2 = (m) aVarC.z(descriptor2, 5, l.f, mVar2);
                    i |= 32;
                    break;
                case 6:
                    mVar = (m) aVarC.z(descriptor2, 6, l.f, mVar);
                    i |= 64;
                    break;
                case 7:
                    j2 = aVarC.j(descriptor2, 7);
                    i |= 128;
                    break;
                case 8:
                    enumC1452f = (EnumC1452f) aVarC.z(descriptor2, 8, C1451e.f, enumC1452f);
                    i |= 256;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new LatestAnswer(i, j, lVar, uVar, iN, num, mVar2, mVar, j2, enumC1452f);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull LatestAnswer value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.a);
        bVarC.i(descriptor2, 1, k.f, value.b);
        bVarC.i(descriptor2, 2, t.f, value.c);
        bVarC.l(3, value.d, descriptor2);
        boolean zD = bVarC.D(descriptor2);
        Integer num = value.e;
        if (zD || num != null) {
            bVarC.s(descriptor2, 4, K.a, num);
        }
        l lVar = l.f;
        bVarC.i(descriptor2, 5, lVar, value.f);
        bVarC.i(descriptor2, 6, lVar, value.g);
        bVarC.C(descriptor2, 7, value.h);
        bVarC.i(descriptor2, 8, C1451e.f, value.i);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
