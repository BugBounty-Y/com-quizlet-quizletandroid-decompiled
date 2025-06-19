package com.quizlet.shared.models.api.studyset;

import com.comscore.streaming.EventType;
import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
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
public final class RemoteStudySet$$serializer implements D {

    @NotNull
    public static final RemoteStudySet$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteStudySet$$serializer remoteStudySet$$serializer = new RemoteStudySet$$serializer();
        INSTANCE = remoteStudySet$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.studyset.RemoteStudySet", remoteStudySet$$serializer, 25);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("creatorId", false);
        pluginGeneratedSerialDescriptor.k("wordLang", false);
        pluginGeneratedSerialDescriptor.k("defLang", false);
        pluginGeneratedSerialDescriptor.k("title", false);
        pluginGeneratedSerialDescriptor.k("passwordUse", false);
        pluginGeneratedSerialDescriptor.k("passwordEdit", false);
        pluginGeneratedSerialDescriptor.k(DBStudySetFields.Names.ACCESS_TYPE, false);
        pluginGeneratedSerialDescriptor.k(DBStudySetFields.Names.ACCESS_CODE_PREFIX, false);
        pluginGeneratedSerialDescriptor.k(OTUXParamsKeys.OT_UX_DESCRIPTION, false);
        pluginGeneratedSerialDescriptor.k("numTerms", false);
        pluginGeneratedSerialDescriptor.k("hasImages", false);
        pluginGeneratedSerialDescriptor.k("parentId", false);
        pluginGeneratedSerialDescriptor.k("creationSource", false);
        pluginGeneratedSerialDescriptor.k("privacyLockStatus", false);
        pluginGeneratedSerialDescriptor.k(DBStudySetFields.Names.HAS_DIAGRAMS, false);
        pluginGeneratedSerialDescriptor.k("_webUrl", false);
        pluginGeneratedSerialDescriptor.k(DBStudySetFields.Names.THUMBNAIL_URL, false);
        pluginGeneratedSerialDescriptor.k("price", false);
        pluginGeneratedSerialDescriptor.k("purchasableType", false);
        pluginGeneratedSerialDescriptor.k("magicNoteUuid", false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k(DBStudySetFields.Names.PUBLISHED_TIMESTAMP, false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteStudySet$$serializer() {
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
        KSerializer kSerializerE5 = R1.e(q0Var);
        C5053g c5053g = C5053g.a;
        KSerializer kSerializerE6 = R1.e(c5053g);
        KSerializer kSerializerE7 = R1.e(c5053g);
        K k = K.a;
        return new KSerializer[]{kSerializerE, kSerializerE2, kSerializerE3, kSerializerE4, kSerializerE5, kSerializerE6, kSerializerE7, R1.e(k), R1.e(q0Var), R1.e(q0Var), R1.e(k), R1.e(c5053g), R1.e(k), R1.e(k), R1.e(k), R1.e(c5053g), R1.e(q0Var), R1.e(q0Var), R1.e(q0Var), R1.e(k), R1.e(q0Var), R1.e(p), R1.e(p), R1.e(p), R1.e(c5053g)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteStudySet deserialize(@NotNull Decoder decoder) {
        Integer num;
        int i;
        Integer num2;
        Long l;
        String str;
        Integer num3;
        Boolean bool;
        Boolean bool2;
        Integer num4;
        Long l2;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        Long l3 = null;
        Integer num5 = null;
        Integer num6 = null;
        Boolean bool3 = null;
        Integer num7 = null;
        Boolean bool4 = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        Integer num8 = null;
        String str5 = null;
        Long l4 = null;
        Long l5 = null;
        Long l6 = null;
        Long l7 = null;
        String str6 = null;
        String str7 = null;
        String str8 = null;
        Boolean bool5 = null;
        Boolean bool6 = null;
        Integer num9 = null;
        String str9 = null;
        String str10 = null;
        Integer num10 = null;
        Boolean bool7 = null;
        int i2 = 0;
        boolean z = true;
        while (z) {
            Integer num11 = num6;
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    String str11 = str8;
                    Integer num12 = num7;
                    Long l8 = l6;
                    Boolean bool8 = bool7;
                    num2 = num5;
                    l = l3;
                    str = str10;
                    num3 = num8;
                    bool = bool5;
                    bool2 = bool4;
                    l6 = l8;
                    num7 = num12;
                    str8 = str11;
                    str4 = str4;
                    str9 = str9;
                    l5 = l5;
                    bool7 = bool8;
                    z = false;
                    bool4 = bool2;
                    num6 = num11;
                    num5 = num2;
                    l3 = l;
                    bool5 = bool;
                    num8 = num3;
                    str10 = str;
                case 0:
                    num = num5;
                    String str12 = str10;
                    String str13 = str8;
                    Integer num13 = num7;
                    Long l9 = l6;
                    Boolean bool9 = bool7;
                    Long l10 = (Long) aVarC.v(descriptor2, 0, P.a, l9);
                    i2 |= 1;
                    num7 = num13;
                    bool4 = bool4;
                    num6 = num11;
                    l3 = l3;
                    str8 = str13;
                    bool5 = bool5;
                    str4 = str4;
                    num8 = num8;
                    str9 = str9;
                    str10 = str12;
                    l5 = l5;
                    bool7 = bool9;
                    l6 = l10;
                    num5 = num;
                case 1:
                    num2 = num5;
                    l = l3;
                    str = str10;
                    num3 = num8;
                    bool = bool5;
                    bool2 = bool4;
                    l7 = (Long) aVarC.v(descriptor2, 1, P.a, l7);
                    i2 |= 2;
                    bool4 = bool2;
                    num6 = num11;
                    num5 = num2;
                    l3 = l;
                    bool5 = bool;
                    num8 = num3;
                    str10 = str;
                case 2:
                    num4 = num5;
                    l2 = l3;
                    str6 = (String) aVarC.v(descriptor2, 2, q0.a, str6);
                    i2 |= 4;
                    num6 = num11;
                    num5 = num4;
                    l3 = l2;
                case 3:
                    num4 = num5;
                    l2 = l3;
                    str7 = (String) aVarC.v(descriptor2, 3, q0.a, str7);
                    i2 |= 8;
                    num6 = num11;
                    num5 = num4;
                    l3 = l2;
                case 4:
                    num4 = num5;
                    l2 = l3;
                    str8 = (String) aVarC.v(descriptor2, 4, q0.a, str8);
                    i2 |= 16;
                    num6 = num11;
                    num5 = num4;
                    l3 = l2;
                case 5:
                    num4 = num5;
                    l2 = l3;
                    bool5 = (Boolean) aVarC.v(descriptor2, 5, C5053g.a, bool5);
                    i2 |= 32;
                    num6 = num11;
                    num5 = num4;
                    l3 = l2;
                case 6:
                    num4 = num5;
                    l2 = l3;
                    bool6 = (Boolean) aVarC.v(descriptor2, 6, C5053g.a, bool6);
                    i2 |= 64;
                    num6 = num11;
                    num5 = num4;
                    l3 = l2;
                case 7:
                    num4 = num5;
                    l2 = l3;
                    num9 = (Integer) aVarC.v(descriptor2, 7, K.a, num9);
                    i2 |= 128;
                    num6 = num11;
                    num5 = num4;
                    l3 = l2;
                case 8:
                    num4 = num5;
                    l2 = l3;
                    str9 = (String) aVarC.v(descriptor2, 8, q0.a, str9);
                    i2 |= 256;
                    num6 = num11;
                    num5 = num4;
                    l3 = l2;
                case 9:
                    num4 = num5;
                    l2 = l3;
                    str10 = (String) aVarC.v(descriptor2, 9, q0.a, str10);
                    i2 |= g.MAX_CONTENT_URL_LENGTH;
                    num6 = num11;
                    num5 = num4;
                    l3 = l2;
                case 10:
                    num4 = num5;
                    l2 = l3;
                    num10 = (Integer) aVarC.v(descriptor2, 10, K.a, num10);
                    i2 |= 1024;
                    num6 = num11;
                    num5 = num4;
                    l3 = l2;
                case 11:
                    num4 = num5;
                    l2 = l3;
                    bool7 = (Boolean) aVarC.v(descriptor2, 11, C5053g.a, bool7);
                    i2 |= 2048;
                    num6 = num11;
                    num5 = num4;
                    l3 = l2;
                case 12:
                    l2 = l3;
                    num4 = num5;
                    num6 = (Integer) aVarC.v(descriptor2, 12, K.a, num11);
                    i2 |= 4096;
                    num5 = num4;
                    l3 = l2;
                case 13:
                    l2 = l3;
                    num5 = (Integer) aVarC.v(descriptor2, 13, K.a, num5);
                    i2 |= 8192;
                    num6 = num11;
                    l3 = l2;
                case 14:
                    num = num5;
                    num7 = (Integer) aVarC.v(descriptor2, 14, K.a, num7);
                    i2 |= 16384;
                    num6 = num11;
                    num5 = num;
                case 15:
                    num = num5;
                    bool4 = (Boolean) aVarC.v(descriptor2, 15, C5053g.a, bool4);
                    i = 32768;
                    i2 |= i;
                    num6 = num11;
                    num5 = num;
                case 16:
                    num = num5;
                    str2 = (String) aVarC.v(descriptor2, 16, q0.a, str2);
                    i = 65536;
                    i2 |= i;
                    num6 = num11;
                    num5 = num;
                case 17:
                    num = num5;
                    str3 = (String) aVarC.v(descriptor2, 17, q0.a, str3);
                    i = 131072;
                    i2 |= i;
                    num6 = num11;
                    num5 = num;
                case 18:
                    num = num5;
                    str4 = (String) aVarC.v(descriptor2, 18, q0.a, str4);
                    i = 262144;
                    i2 |= i;
                    num6 = num11;
                    num5 = num;
                case 19:
                    num = num5;
                    num8 = (Integer) aVarC.v(descriptor2, 19, K.a, num8);
                    i = 524288;
                    i2 |= i;
                    num6 = num11;
                    num5 = num;
                case 20:
                    num = num5;
                    str5 = (String) aVarC.v(descriptor2, 20, q0.a, str5);
                    i = 1048576;
                    i2 |= i;
                    num6 = num11;
                    num5 = num;
                case 21:
                    num = num5;
                    l4 = (Long) aVarC.v(descriptor2, 21, P.a, l4);
                    i = 2097152;
                    i2 |= i;
                    num6 = num11;
                    num5 = num;
                case EventType.WINDOW_STATE /* 22 */:
                    num = num5;
                    l5 = (Long) aVarC.v(descriptor2, 22, P.a, l5);
                    i = 4194304;
                    i2 |= i;
                    num6 = num11;
                    num5 = num;
                case EventType.AUDIO /* 23 */:
                    num = num5;
                    l3 = (Long) aVarC.v(descriptor2, 23, P.a, l3);
                    i = 8388608;
                    i2 |= i;
                    num6 = num11;
                    num5 = num;
                case EventType.VIDEO /* 24 */:
                    num = num5;
                    bool3 = (Boolean) aVarC.v(descriptor2, 24, C5053g.a, bool3);
                    i = 16777216;
                    i2 |= i;
                    num6 = num11;
                    num5 = num;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        String str14 = str8;
        Integer num14 = num7;
        Long l11 = l6;
        Boolean bool10 = bool7;
        Long l12 = l5;
        Integer num15 = num5;
        Integer num16 = num6;
        Long l13 = l3;
        String str15 = str6;
        String str16 = str10;
        Integer num17 = num8;
        Boolean bool11 = bool5;
        Boolean bool12 = bool4;
        Long l14 = l7;
        aVarC.b(descriptor2);
        Long l15 = l4;
        return new RemoteStudySet(i2, l11, l14, str15, str7, str14, bool11, bool6, num9, str9, str16, num10, bool10, num16, num15, num14, bool12, str2, str3, str4, num17, str5, l15, l12, l13, bool3);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteStudySet value) {
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
        bVarC.s(descriptor2, 4, q0Var, value.e);
        C5053g c5053g = C5053g.a;
        bVarC.s(descriptor2, 5, c5053g, value.f);
        bVarC.s(descriptor2, 6, c5053g, value.g);
        K k = K.a;
        bVarC.s(descriptor2, 7, k, value.h);
        bVarC.s(descriptor2, 8, q0Var, value.i);
        bVarC.s(descriptor2, 9, q0Var, value.j);
        bVarC.s(descriptor2, 10, k, value.k);
        bVarC.s(descriptor2, 11, c5053g, value.l);
        bVarC.s(descriptor2, 12, k, value.m);
        bVarC.s(descriptor2, 13, k, value.n);
        bVarC.s(descriptor2, 14, k, value.o);
        bVarC.s(descriptor2, 15, c5053g, value.p);
        bVarC.s(descriptor2, 16, q0Var, value.q);
        bVarC.s(descriptor2, 17, q0Var, value.r);
        bVarC.s(descriptor2, 18, q0Var, value.s);
        bVarC.s(descriptor2, 19, k, value.t);
        bVarC.s(descriptor2, 20, q0Var, value.u);
        bVarC.s(descriptor2, 21, p, value.v);
        bVarC.s(descriptor2, 22, p, value.w);
        bVarC.s(descriptor2, 23, p, value.x);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.y;
        if (zD || bool != null) {
            bVarC.s(descriptor2, 24, c5053g, bool);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
