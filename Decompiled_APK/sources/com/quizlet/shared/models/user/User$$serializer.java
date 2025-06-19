package com.quizlet.shared.models.user;

import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.shared.enums.j;
import com.quizlet.shared.enums.u;
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
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class User$$serializer implements D {

    @NotNull
    public static final User$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        User$$serializer user$$serializer = new User$$serializer();
        INSTANCE = user$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("User", user$$serializer, 14);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("username", false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.IS_VERIFIED, false);
        pluginGeneratedSerialDescriptor.k("upgradeType", false);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE, false);
        pluginGeneratedSerialDescriptor.k("isLocked", false);
        pluginGeneratedSerialDescriptor.k("imageURL", false);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.TIME_ZONE, false);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.PROFILE_IMAGE_ID, false);
        pluginGeneratedSerialDescriptor.k("isDeleted", false);
        pluginGeneratedSerialDescriptor.k("numCreatedSets", false);
        pluginGeneratedSerialDescriptor.k("numClassMemberships", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private User$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = User.p;
        q0 q0Var = q0.a;
        KSerializer kSerializer = kSerializerArr[5];
        KSerializer kSerializer2 = kSerializerArr[6];
        KSerializer kSerializerE = R1.e(q0Var);
        P p = P.a;
        C5053g c5053g = C5053g.a;
        K k = K.a;
        return new KSerializer[]{p, q0Var, p, p, c5053g, kSerializer, kSerializer2, c5053g, q0Var, q0Var, kSerializerE, c5053g, k, k};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public User deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = User.p;
        u uVar = null;
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        j jVar = null;
        String str = null;
        String strR = null;
        String strR2 = null;
        String strR3 = null;
        boolean z = true;
        int i = 0;
        boolean zQ = false;
        boolean zQ2 = false;
        boolean zQ3 = false;
        int iN = 0;
        int iN2 = 0;
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
                    strR = aVarC.r(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    j2 = aVarC.j(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    j3 = aVarC.j(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    zQ = aVarC.q(descriptor2, 4);
                    i |= 16;
                    break;
                case 5:
                    uVar = (u) aVarC.z(descriptor2, 5, kSerializerArr[5], uVar);
                    i |= 32;
                    break;
                case 6:
                    jVar = (j) aVarC.z(descriptor2, 6, kSerializerArr[6], jVar);
                    i |= 64;
                    break;
                case 7:
                    zQ2 = aVarC.q(descriptor2, 7);
                    i |= 128;
                    break;
                case 8:
                    strR2 = aVarC.r(descriptor2, 8);
                    i |= 256;
                    break;
                case 9:
                    strR3 = aVarC.r(descriptor2, 9);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    break;
                case 10:
                    str = (String) aVarC.v(descriptor2, 10, q0.a, str);
                    i |= 1024;
                    break;
                case 11:
                    zQ3 = aVarC.q(descriptor2, 11);
                    i |= 2048;
                    break;
                case 12:
                    iN = aVarC.n(descriptor2, 12);
                    i |= 4096;
                    break;
                case 13:
                    iN2 = aVarC.n(descriptor2, 13);
                    i |= 8192;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new User(i, j, strR, j2, j3, zQ, uVar, jVar, zQ2, strR2, strR3, str, zQ3, iN, iN2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull User value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.b);
        bVarC.r(descriptor2, 1, value.c);
        bVarC.C(descriptor2, 2, value.d);
        bVarC.C(descriptor2, 3, value.e);
        bVarC.p(descriptor2, 4, value.f);
        KSerializer[] kSerializerArr = User.p;
        bVarC.i(descriptor2, 5, kSerializerArr[5], value.g);
        bVarC.i(descriptor2, 6, kSerializerArr[6], value.h);
        bVarC.p(descriptor2, 7, value.i);
        bVarC.r(descriptor2, 8, value.j);
        bVarC.r(descriptor2, 9, value.k);
        bVarC.s(descriptor2, 10, q0.a, value.l);
        bVarC.p(descriptor2, 11, value.m);
        bVarC.l(12, value.n, descriptor2);
        bVarC.l(13, value.o, descriptor2);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
