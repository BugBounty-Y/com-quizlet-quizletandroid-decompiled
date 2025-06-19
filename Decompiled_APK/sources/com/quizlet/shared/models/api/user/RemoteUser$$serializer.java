package com.quizlet.shared.models.api.user;

import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
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
public final class RemoteUser$$serializer implements D {

    @NotNull
    public static final RemoteUser$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteUser$$serializer remoteUser$$serializer = new RemoteUser$$serializer();
        INSTANCE = remoteUser$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.user.RemoteUser", remoteUser$$serializer, 14);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("username", false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.IS_VERIFIED, true);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.USER_UPGRADE_TYPE, false);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE, false);
        pluginGeneratedSerialDescriptor.k("isLocked", false);
        pluginGeneratedSerialDescriptor.k("_imageUrl", true);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.TIME_ZONE, false);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.PROFILE_IMAGE_ID, true);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        pluginGeneratedSerialDescriptor.k("_numCreatedSets", true);
        pluginGeneratedSerialDescriptor.k("_numClassMemberships", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteUser$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        P p = P.a;
        KSerializer kSerializerE = R1.e(p);
        q0 q0Var = q0.a;
        KSerializer kSerializerE2 = R1.e(q0Var);
        KSerializer kSerializerE3 = R1.e(p);
        KSerializer kSerializerE4 = R1.e(p);
        C5053g c5053g = C5053g.a;
        KSerializer kSerializerE5 = R1.e(c5053g);
        K k = K.a;
        return new KSerializer[]{kSerializerE, kSerializerE2, kSerializerE3, kSerializerE4, kSerializerE5, R1.e(k), R1.e(k), R1.e(c5053g), R1.e(q0Var), R1.e(q0Var), R1.e(q0Var), c5053g, R1.e(k), R1.e(k)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteUser deserialize(@NotNull Decoder decoder) {
        String str;
        String str2;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        String str3 = null;
        Integer num = null;
        String str4 = null;
        Integer num2 = null;
        Long l = null;
        String str5 = null;
        Long l2 = null;
        Long l3 = null;
        Boolean bool = null;
        Integer num3 = null;
        Integer num4 = null;
        Boolean bool2 = null;
        String str6 = null;
        int i = 0;
        boolean z = true;
        boolean zQ = false;
        while (z) {
            Long l4 = l;
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    str2 = str5;
                    l = l4;
                    z = false;
                    i = i;
                    str5 = str2;
                case 0:
                    str2 = str5;
                    l = (Long) aVarC.v(descriptor2, 0, P.a, l4);
                    i |= 1;
                    str5 = str2;
                case 1:
                    str5 = (String) aVarC.v(descriptor2, 1, q0.a, str5);
                    i |= 2;
                    l = l4;
                case 2:
                    str = str5;
                    l2 = (Long) aVarC.v(descriptor2, 2, P.a, l2);
                    i |= 4;
                    l = l4;
                    str5 = str;
                case 3:
                    str = str5;
                    l3 = (Long) aVarC.v(descriptor2, 3, P.a, l3);
                    i |= 8;
                    l = l4;
                    str5 = str;
                case 4:
                    str = str5;
                    bool = (Boolean) aVarC.v(descriptor2, 4, C5053g.a, bool);
                    i |= 16;
                    l = l4;
                    str5 = str;
                case 5:
                    str = str5;
                    num3 = (Integer) aVarC.v(descriptor2, 5, K.a, num3);
                    i |= 32;
                    l = l4;
                    str5 = str;
                case 6:
                    str = str5;
                    num4 = (Integer) aVarC.v(descriptor2, 6, K.a, num4);
                    i |= 64;
                    l = l4;
                    str5 = str;
                case 7:
                    str = str5;
                    bool2 = (Boolean) aVarC.v(descriptor2, 7, C5053g.a, bool2);
                    i |= 128;
                    l = l4;
                    str5 = str;
                case 8:
                    str = str5;
                    str6 = (String) aVarC.v(descriptor2, 8, q0.a, str6);
                    i |= 256;
                    l = l4;
                    str5 = str;
                case 9:
                    str = str5;
                    str3 = (String) aVarC.v(descriptor2, 9, q0.a, str3);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    l = l4;
                    str5 = str;
                case 10:
                    str = str5;
                    str4 = (String) aVarC.v(descriptor2, 10, q0.a, str4);
                    i |= 1024;
                    l = l4;
                    str5 = str;
                case 11:
                    zQ = aVarC.q(descriptor2, 11);
                    i |= 2048;
                    l = l4;
                case 12:
                    str = str5;
                    num2 = (Integer) aVarC.v(descriptor2, 12, K.a, num2);
                    i |= 4096;
                    l = l4;
                    str5 = str;
                case 13:
                    str = str5;
                    num = (Integer) aVarC.v(descriptor2, 13, K.a, num);
                    i |= 8192;
                    l = l4;
                    str5 = str;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new RemoteUser(i, l, str5, l2, l3, bool, num3, num4, bool2, str6, str3, str4, zQ, num2, num);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteUser value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        P p = P.a;
        bVarC.s(descriptor2, 0, p, value.a);
        q0 q0Var = q0.a;
        bVarC.s(descriptor2, 1, q0Var, value.b);
        bVarC.s(descriptor2, 2, p, value.c);
        bVarC.s(descriptor2, 3, p, value.d);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.e;
        if (zD || !Intrinsics.b(bool, Boolean.FALSE)) {
            bVarC.s(descriptor2, 4, C5053g.a, bool);
        }
        K k = K.a;
        bVarC.s(descriptor2, 5, k, value.f);
        bVarC.s(descriptor2, 6, k, value.g);
        bVarC.s(descriptor2, 7, C5053g.a, value.h);
        boolean zD2 = bVarC.D(descriptor2);
        String str = value.i;
        if (zD2 || str != null) {
            bVarC.s(descriptor2, 8, q0Var, str);
        }
        bVarC.s(descriptor2, 9, q0Var, value.j);
        boolean zD3 = bVarC.D(descriptor2);
        String str2 = value.k;
        if (zD3 || str2 != null) {
            bVarC.s(descriptor2, 10, q0Var, str2);
        }
        boolean zD4 = bVarC.D(descriptor2);
        boolean z = value.l;
        if (zD4 || z) {
            bVarC.p(descriptor2, 11, z);
        }
        boolean zD5 = bVarC.D(descriptor2);
        Integer num = value.m;
        if (zD5 || num != null) {
            bVarC.s(descriptor2, 12, k, num);
        }
        boolean zD6 = bVarC.D(descriptor2);
        Integer num2 = value.n;
        if (zD6 || num2 != null) {
            bVarC.s(descriptor2, 13, k, num2);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
