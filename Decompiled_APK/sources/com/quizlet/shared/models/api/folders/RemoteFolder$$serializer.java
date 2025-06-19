package com.quizlet.shared.models.api.folders;

import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.db.data.models.persisted.fields.DBFolderFields;
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
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class RemoteFolder$$serializer implements D {

    @NotNull
    public static final RemoteFolder$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteFolder$$serializer remoteFolder$$serializer = new RemoteFolder$$serializer();
        INSTANCE = remoteFolder$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.folders.RemoteFolder", remoteFolder$$serializer, 10);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("personId", false);
        pluginGeneratedSerialDescriptor.k("name", false);
        pluginGeneratedSerialDescriptor.k(OTUXParamsKeys.OT_UX_DESCRIPTION, false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k(DBFolderFields.Names.NUM_SETS, false);
        pluginGeneratedSerialDescriptor.k("isHidden", false);
        pluginGeneratedSerialDescriptor.k("_webUrl", false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteFolder$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        P p = P.a;
        KSerializer kSerializerE = R1.e(p);
        KSerializer kSerializerE2 = R1.e(p);
        q0 q0Var = q0.a;
        KSerializer kSerializerE3 = R1.e(q0Var);
        KSerializer kSerializerE4 = R1.e(q0Var);
        KSerializer kSerializerE5 = R1.e(p);
        KSerializer kSerializerE6 = R1.e(p);
        KSerializer kSerializerE7 = R1.e(p);
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{kSerializerE, kSerializerE2, kSerializerE3, kSerializerE4, kSerializerE5, kSerializerE6, kSerializerE7, R1.e(c5053g), R1.e(q0Var), R1.e(c5053g)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteFolder deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        Boolean bool = null;
        Long l = null;
        Long l2 = null;
        String str = null;
        String str2 = null;
        Long l3 = null;
        Long l4 = null;
        Long l5 = null;
        Boolean bool2 = null;
        String str3 = null;
        boolean z = true;
        int i = 0;
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
                    l2 = (Long) aVarC.v(descriptor2, 1, P.a, l2);
                    i |= 2;
                    break;
                case 2:
                    str = (String) aVarC.v(descriptor2, 2, q0.a, str);
                    i |= 4;
                    break;
                case 3:
                    str2 = (String) aVarC.v(descriptor2, 3, q0.a, str2);
                    i |= 8;
                    break;
                case 4:
                    l3 = (Long) aVarC.v(descriptor2, 4, P.a, l3);
                    i |= 16;
                    break;
                case 5:
                    l4 = (Long) aVarC.v(descriptor2, 5, P.a, l4);
                    i |= 32;
                    break;
                case 6:
                    l5 = (Long) aVarC.v(descriptor2, 6, P.a, l5);
                    i |= 64;
                    break;
                case 7:
                    bool2 = (Boolean) aVarC.v(descriptor2, 7, C5053g.a, bool2);
                    i |= 128;
                    break;
                case 8:
                    str3 = (String) aVarC.v(descriptor2, 8, q0.a, str3);
                    i |= 256;
                    break;
                case 9:
                    bool = (Boolean) aVarC.v(descriptor2, 9, C5053g.a, bool);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new RemoteFolder(i, l, l2, str, str2, l3, l4, l5, bool2, str3, bool);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteFolder value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        P p = P.a;
        bVarC.s(descriptor2, 0, p, value.a);
        bVarC.s(descriptor2, 1, p, value.b);
        q0 q0Var = q0.a;
        bVarC.s(descriptor2, 2, q0Var, value.c);
        bVarC.s(descriptor2, 3, q0Var, value.d);
        bVarC.s(descriptor2, 4, p, value.e);
        bVarC.s(descriptor2, 5, p, value.f);
        bVarC.s(descriptor2, 6, p, value.g);
        C5053g c5053g = C5053g.a;
        bVarC.s(descriptor2, 7, c5053g, value.h);
        bVarC.s(descriptor2, 8, q0Var, value.i);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.j;
        if (zD || bool != null) {
            bVarC.s(descriptor2, 9, c5053g, bool);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
