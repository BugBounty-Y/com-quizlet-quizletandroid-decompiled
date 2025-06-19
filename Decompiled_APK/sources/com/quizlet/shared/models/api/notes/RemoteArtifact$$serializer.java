package com.quizlet.shared.models.api.notes;

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
public final class RemoteArtifact$$serializer implements D {

    @NotNull
    public static final RemoteArtifact$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteArtifact$$serializer remoteArtifact$$serializer = new RemoteArtifact$$serializer();
        INSTANCE = remoteArtifact$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.notes.RemoteArtifact", remoteArtifact$$serializer, 10);
        pluginGeneratedSerialDescriptor.k("uuid", false);
        pluginGeneratedSerialDescriptor.k("noteUuid", false);
        pluginGeneratedSerialDescriptor.k("userId", false);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.USER_UPGRADE_TYPE, false);
        pluginGeneratedSerialDescriptor.k("status", false);
        pluginGeneratedSerialDescriptor.k("content", false);
        pluginGeneratedSerialDescriptor.k("createdAt", false);
        pluginGeneratedSerialDescriptor.k("updatedAt", false);
        pluginGeneratedSerialDescriptor.k("history", false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteArtifact$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        return new KSerializer[]{R1.e(q0Var), R1.e(q0Var), R1.e(P.a), R1.e(q0Var), R1.e(K.a), R1.e(q0Var), R1.e(q0Var), R1.e(q0Var), R1.e(q0Var), R1.e(C5053g.a)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteArtifact deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        Boolean bool = null;
        String str = null;
        String str2 = null;
        Long l = null;
        String str3 = null;
        Integer num = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        String str7 = null;
        boolean z = true;
        int i = 0;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    str = (String) aVarC.v(descriptor2, 0, q0.a, str);
                    i |= 1;
                    break;
                case 1:
                    str2 = (String) aVarC.v(descriptor2, 1, q0.a, str2);
                    i |= 2;
                    break;
                case 2:
                    l = (Long) aVarC.v(descriptor2, 2, P.a, l);
                    i |= 4;
                    break;
                case 3:
                    str3 = (String) aVarC.v(descriptor2, 3, q0.a, str3);
                    i |= 8;
                    break;
                case 4:
                    num = (Integer) aVarC.v(descriptor2, 4, K.a, num);
                    i |= 16;
                    break;
                case 5:
                    str4 = (String) aVarC.v(descriptor2, 5, q0.a, str4);
                    i |= 32;
                    break;
                case 6:
                    str5 = (String) aVarC.v(descriptor2, 6, q0.a, str5);
                    i |= 64;
                    break;
                case 7:
                    str6 = (String) aVarC.v(descriptor2, 7, q0.a, str6);
                    i |= 128;
                    break;
                case 8:
                    str7 = (String) aVarC.v(descriptor2, 8, q0.a, str7);
                    i |= 256;
                    break;
                case 9:
                    bool = (Boolean) aVarC.v(descriptor2, 9, C5053g.a, bool);
                    i |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new RemoteArtifact(i, str, str2, l, str3, num, str4, str5, str6, str7, bool);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteArtifact value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        q0 q0Var = q0.a;
        bVarC.s(descriptor2, 0, q0Var, value.a);
        bVarC.s(descriptor2, 1, q0Var, value.b);
        bVarC.s(descriptor2, 2, P.a, value.c);
        bVarC.s(descriptor2, 3, q0Var, value.d);
        bVarC.s(descriptor2, 4, K.a, value.e);
        bVarC.s(descriptor2, 5, q0Var, value.f);
        bVarC.s(descriptor2, 6, q0Var, value.g);
        bVarC.s(descriptor2, 7, q0Var, value.h);
        bVarC.s(descriptor2, 8, q0Var, value.i);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.j;
        if (zD || bool != null) {
            bVarC.s(descriptor2, 9, C5053g.a, bool);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
