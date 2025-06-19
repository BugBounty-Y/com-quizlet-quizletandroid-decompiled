package com.quizlet.shared.models.api.explanations;

import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
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
public final class RemoteTextbook$$serializer implements D {

    @NotNull
    public static final RemoteTextbook$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteTextbook$$serializer remoteTextbook$$serializer = new RemoteTextbook$$serializer();
        INSTANCE = remoteTextbook$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.explanations.RemoteTextbook", remoteTextbook$$serializer, 14);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("isbn", false);
        pluginGeneratedSerialDescriptor.k("title", false);
        pluginGeneratedSerialDescriptor.k("authors", false);
        pluginGeneratedSerialDescriptor.k("imageUrl", false);
        pluginGeneratedSerialDescriptor.k("imageThumbnailUrl", false);
        pluginGeneratedSerialDescriptor.k("isPremium", false);
        pluginGeneratedSerialDescriptor.k("edition", false);
        pluginGeneratedSerialDescriptor.k("verifiedSolutionCount", false);
        pluginGeneratedSerialDescriptor.k("_hasSolutions", false);
        pluginGeneratedSerialDescriptor.k("_webUrl", false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteTextbook$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        P p = P.a;
        KSerializer kSerializerE = R1.e(p);
        q0 q0Var = q0.a;
        KSerializer kSerializerE2 = R1.e(q0Var);
        KSerializer kSerializerE3 = R1.e(q0Var);
        KSerializer kSerializerE4 = R1.e(q0Var);
        KSerializer kSerializerE5 = R1.e(q0Var);
        KSerializer kSerializerE6 = R1.e(q0Var);
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{kSerializerE, kSerializerE2, kSerializerE3, kSerializerE4, kSerializerE5, kSerializerE6, R1.e(c5053g), R1.e(q0Var), R1.e(K.a), R1.e(c5053g), R1.e(q0Var), R1.e(p), R1.e(p), R1.e(c5053g)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteTextbook deserialize(@NotNull Decoder decoder) {
        String str;
        Boolean bool;
        String str2;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        Boolean bool2 = null;
        Boolean bool3 = null;
        Long l = null;
        String str3 = null;
        Long l2 = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        String str7 = null;
        String str8 = null;
        Boolean bool4 = null;
        String str9 = null;
        Integer num = null;
        Long l3 = null;
        int i = 0;
        boolean z = true;
        while (z) {
            String str10 = str4;
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    bool = bool3;
                    str2 = str5;
                    i = i;
                    l2 = l2;
                    l3 = l3;
                    str4 = str10;
                    z = false;
                    str5 = str2;
                    bool3 = bool;
                case 0:
                    bool = bool3;
                    str2 = str5;
                    Long l4 = l3;
                    Long l5 = l2;
                    i |= 1;
                    l2 = l5;
                    l3 = (Long) aVarC.v(descriptor2, 0, P.a, l4);
                    str4 = str10;
                    str5 = str2;
                    bool3 = bool;
                case 1:
                    bool = bool3;
                    str2 = str5;
                    str4 = (String) aVarC.v(descriptor2, 1, q0.a, str10);
                    i |= 2;
                    str5 = str2;
                    bool3 = bool;
                case 2:
                    bool = bool3;
                    str5 = (String) aVarC.v(descriptor2, 2, q0.a, str5);
                    i |= 4;
                    str4 = str10;
                    bool3 = bool;
                case 3:
                    str = str5;
                    str6 = (String) aVarC.v(descriptor2, 3, q0.a, str6);
                    i |= 8;
                    str4 = str10;
                    str5 = str;
                case 4:
                    str = str5;
                    str7 = (String) aVarC.v(descriptor2, 4, q0.a, str7);
                    i |= 16;
                    str4 = str10;
                    str5 = str;
                case 5:
                    str = str5;
                    str8 = (String) aVarC.v(descriptor2, 5, q0.a, str8);
                    i |= 32;
                    str4 = str10;
                    str5 = str;
                case 6:
                    str = str5;
                    bool4 = (Boolean) aVarC.v(descriptor2, 6, C5053g.a, bool4);
                    i |= 64;
                    str4 = str10;
                    str5 = str;
                case 7:
                    str = str5;
                    str9 = (String) aVarC.v(descriptor2, 7, q0.a, str9);
                    i |= 128;
                    str4 = str10;
                    str5 = str;
                case 8:
                    str = str5;
                    num = (Integer) aVarC.v(descriptor2, 8, K.a, num);
                    i |= 256;
                    str4 = str10;
                    str5 = str;
                case 9:
                    str = str5;
                    bool2 = (Boolean) aVarC.v(descriptor2, 9, C5053g.a, bool2);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    str4 = str10;
                    str5 = str;
                case 10:
                    str = str5;
                    str3 = (String) aVarC.v(descriptor2, 10, q0.a, str3);
                    i |= 1024;
                    str4 = str10;
                    str5 = str;
                case 11:
                    str = str5;
                    l2 = (Long) aVarC.v(descriptor2, 11, P.a, l2);
                    i |= 2048;
                    str4 = str10;
                    str5 = str;
                case 12:
                    str = str5;
                    l = (Long) aVarC.v(descriptor2, 12, P.a, l);
                    i |= 4096;
                    str4 = str10;
                    str5 = str;
                case 13:
                    str = str5;
                    bool3 = (Boolean) aVarC.v(descriptor2, 13, C5053g.a, bool3);
                    i |= 8192;
                    str4 = str10;
                    str5 = str;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        Long l6 = l3;
        Long l7 = l2;
        aVarC.b(descriptor2);
        return new RemoteTextbook(i, l6, str4, str5, str6, str7, str8, bool4, str9, num, bool2, str3, l7, l, bool3);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteTextbook value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        P p = P.a;
        bVarC.s(descriptor2, 0, p, value.a);
        q0 q0Var = q0.a;
        bVarC.s(descriptor2, 1, q0Var, value.b);
        bVarC.s(descriptor2, 2, q0Var, value.c);
        bVarC.s(descriptor2, 3, q0Var, value.d);
        bVarC.s(descriptor2, 4, q0Var, value.e);
        bVarC.s(descriptor2, 5, q0Var, value.f);
        C5053g c5053g = C5053g.a;
        bVarC.s(descriptor2, 6, c5053g, value.g);
        bVarC.s(descriptor2, 7, q0Var, value.h);
        bVarC.s(descriptor2, 8, K.a, value.i);
        bVarC.s(descriptor2, 9, c5053g, value.j);
        bVarC.s(descriptor2, 10, q0Var, value.k);
        bVarC.s(descriptor2, 11, p, value.l);
        bVarC.s(descriptor2, 12, p, value.m);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.n;
        if (zD || bool != null) {
            bVarC.s(descriptor2, 13, c5053g, bool);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
