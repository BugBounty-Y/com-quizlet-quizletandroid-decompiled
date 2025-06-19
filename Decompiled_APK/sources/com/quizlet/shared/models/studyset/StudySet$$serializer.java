package com.quizlet.shared.models.studyset;

import com.comscore.streaming.EventType;
import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.shared.models.user.User;
import com.quizlet.shared.models.user.User$$serializer;
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
public final class StudySet$$serializer implements D {

    @NotNull
    public static final StudySet$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        StudySet$$serializer studySet$$serializer = new StudySet$$serializer();
        INSTANCE = studySet$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("StudySet", studySet$$serializer, 23);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k(DBStudySetFields.Names.PUBLISHED_TIMESTAMP, false);
        pluginGeneratedSerialDescriptor.k("user", false);
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
        pluginGeneratedSerialDescriptor.k("webUrl", false);
        pluginGeneratedSerialDescriptor.k("thumbnailUrl", false);
        pluginGeneratedSerialDescriptor.k("magicNoteUuid", false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private StudySet$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        C5053g c5053g = C5053g.a;
        KSerializer kSerializerE = R1.e(q0Var);
        KSerializer kSerializerE2 = R1.e(q0Var);
        KSerializer kSerializerE3 = R1.e(q0Var);
        KSerializer kSerializerE4 = R1.e(q0Var);
        KSerializer kSerializerE5 = R1.e(c5053g);
        P p = P.a;
        K k = K.a;
        return new KSerializer[]{p, p, p, p, User$$serializer.INSTANCE, q0Var, q0Var, q0Var, c5053g, c5053g, k, kSerializerE, q0Var, k, c5053g, k, k, k, c5053g, kSerializerE2, kSerializerE3, kSerializerE4, kSerializerE5};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public StudySet deserialize(@NotNull Decoder decoder) {
        int i;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        User user = null;
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        long j4 = 0;
        Boolean bool = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String strR = null;
        String strR2 = null;
        String strR3 = null;
        String strR4 = null;
        int i2 = 0;
        boolean z = true;
        boolean zQ = false;
        boolean zQ2 = false;
        int iN = 0;
        int iN2 = 0;
        boolean zQ3 = false;
        int iN3 = 0;
        int iN4 = 0;
        int iN5 = 0;
        boolean zQ4 = false;
        while (true) {
            long j5 = j;
            if (!z) {
                aVarC.b(descriptor2);
                return new StudySet(i2, j, j2, j3, j4, user, strR, strR2, strR3, zQ, zQ2, iN, str, strR4, iN2, zQ3, iN3, iN4, iN5, zQ4, str2, str3, str4, bool);
            }
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    continue;
                    j = j5;
                case 0:
                    j5 = aVarC.j(descriptor2, 0);
                    i2 |= 1;
                    continue;
                    j = j5;
                case 1:
                    j2 = aVarC.j(descriptor2, 1);
                    i2 |= 2;
                    continue;
                    j = j5;
                case 2:
                    j3 = aVarC.j(descriptor2, 2);
                    i2 |= 4;
                    continue;
                    j = j5;
                case 3:
                    j4 = aVarC.j(descriptor2, 3);
                    i2 |= 8;
                    continue;
                    j = j5;
                case 4:
                    user = (User) aVarC.z(descriptor2, 4, User$$serializer.INSTANCE, user);
                    i2 |= 16;
                    continue;
                    j = j5;
                case 5:
                    strR = aVarC.r(descriptor2, 5);
                    i2 |= 32;
                    continue;
                    j = j5;
                case 6:
                    strR2 = aVarC.r(descriptor2, 6);
                    i2 |= 64;
                    continue;
                    j = j5;
                case 7:
                    strR3 = aVarC.r(descriptor2, 7);
                    i2 |= 128;
                    continue;
                    j = j5;
                case 8:
                    zQ = aVarC.q(descriptor2, 8);
                    i2 |= 256;
                    continue;
                    j = j5;
                case 9:
                    zQ2 = aVarC.q(descriptor2, 9);
                    i2 |= g.MAX_CONTENT_URL_LENGTH;
                    continue;
                    j = j5;
                case 10:
                    iN = aVarC.n(descriptor2, 10);
                    i2 |= 1024;
                    continue;
                    j = j5;
                case 11:
                    str = (String) aVarC.v(descriptor2, 11, q0.a, str);
                    i2 |= 2048;
                    continue;
                    j = j5;
                case 12:
                    strR4 = aVarC.r(descriptor2, 12);
                    i2 |= 4096;
                    continue;
                    j = j5;
                case 13:
                    iN2 = aVarC.n(descriptor2, 13);
                    i2 |= 8192;
                    continue;
                    j = j5;
                case 14:
                    zQ3 = aVarC.q(descriptor2, 14);
                    i2 |= 16384;
                    continue;
                    j = j5;
                case 15:
                    iN3 = aVarC.n(descriptor2, 15);
                    i = 32768;
                    break;
                case 16:
                    iN4 = aVarC.n(descriptor2, 16);
                    i = 65536;
                    break;
                case 17:
                    iN5 = aVarC.n(descriptor2, 17);
                    i = 131072;
                    break;
                case 18:
                    zQ4 = aVarC.q(descriptor2, 18);
                    i = 262144;
                    break;
                case 19:
                    str2 = (String) aVarC.v(descriptor2, 19, q0.a, str2);
                    i = 524288;
                    break;
                case 20:
                    str3 = (String) aVarC.v(descriptor2, 20, q0.a, str3);
                    i = 1048576;
                    break;
                case 21:
                    str4 = (String) aVarC.v(descriptor2, 21, q0.a, str4);
                    i = 2097152;
                    break;
                case EventType.WINDOW_STATE /* 22 */:
                    bool = (Boolean) aVarC.v(descriptor2, 22, C5053g.a, bool);
                    i = 4194304;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
            i2 |= i;
            j = j5;
        }
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull StudySet value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.b);
        bVarC.C(descriptor2, 1, value.c);
        bVarC.C(descriptor2, 2, value.d);
        bVarC.C(descriptor2, 3, value.e);
        bVarC.i(descriptor2, 4, User$$serializer.INSTANCE, value.f);
        bVarC.r(descriptor2, 5, value.g);
        bVarC.r(descriptor2, 6, value.h);
        bVarC.r(descriptor2, 7, value.i);
        bVarC.p(descriptor2, 8, value.j);
        bVarC.p(descriptor2, 9, value.k);
        bVarC.l(10, value.l, descriptor2);
        q0 q0Var = q0.a;
        bVarC.s(descriptor2, 11, q0Var, value.m);
        bVarC.r(descriptor2, 12, value.n);
        bVarC.l(13, value.o, descriptor2);
        bVarC.p(descriptor2, 14, value.p);
        bVarC.l(15, value.q, descriptor2);
        bVarC.l(16, value.r, descriptor2);
        bVarC.l(17, value.s, descriptor2);
        bVarC.p(descriptor2, 18, value.t);
        bVarC.s(descriptor2, 19, q0Var, value.u);
        bVarC.s(descriptor2, 20, q0Var, value.v);
        bVarC.s(descriptor2, 21, q0Var, value.w);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.x;
        if (zD || bool != null) {
            bVarC.s(descriptor2, 22, C5053g.a, bool);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
