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
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class RemoteTextbookExercise$$serializer implements D {

    @NotNull
    public static final RemoteTextbookExercise$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteTextbookExercise$$serializer remoteTextbookExercise$$serializer = new RemoteTextbookExercise$$serializer();
        INSTANCE = remoteTextbookExercise$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.explanations.RemoteTextbookExercise", remoteTextbookExercise$$serializer, 15);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("mediaExerciseId", false);
        pluginGeneratedSerialDescriptor.k("exerciseName", false);
        pluginGeneratedSerialDescriptor.k("chapterName", false);
        pluginGeneratedSerialDescriptor.k("chapterTitle", false);
        pluginGeneratedSerialDescriptor.k("groupTitle", false);
        pluginGeneratedSerialDescriptor.k("sectionName", false);
        pluginGeneratedSerialDescriptor.k("sectionTitle", false);
        pluginGeneratedSerialDescriptor.k("pageNumber", false);
        pluginGeneratedSerialDescriptor.k("isPremium", false);
        pluginGeneratedSerialDescriptor.k("_webUrl", false);
        pluginGeneratedSerialDescriptor.k("textbook", false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteTextbookExercise$$serializer() {
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
        KSerializer kSerializerE7 = R1.e(q0Var);
        KSerializer kSerializerE8 = R1.e(q0Var);
        KSerializer kSerializerE9 = R1.e(q0Var);
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{kSerializerE, kSerializerE2, kSerializerE3, kSerializerE4, kSerializerE5, kSerializerE6, kSerializerE7, kSerializerE8, kSerializerE9, R1.e(c5053g), R1.e(q0Var), R1.e(RemoteTextbook$$serializer.INSTANCE), R1.e(p), R1.e(p), R1.e(c5053g)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteTextbookExercise deserialize(@NotNull Decoder decoder) {
        String str;
        boolean z;
        Long l;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        Boolean bool = null;
        Long l2 = null;
        Long l3 = null;
        String str2 = null;
        RemoteTextbook remoteTextbook = null;
        Boolean bool2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        String str7 = null;
        String str8 = null;
        String str9 = null;
        Long l4 = null;
        String str10 = null;
        int i = 0;
        boolean z2 = true;
        while (z2) {
            String str11 = str3;
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    str3 = str11;
                    l2 = l2;
                    i = i;
                    remoteTextbook = remoteTextbook;
                    z2 = false;
                    str4 = str4;
                    l4 = l4;
                    bool2 = bool2;
                case 0:
                    z = z2;
                    str3 = str11;
                    str4 = str4;
                    l2 = l2;
                    i |= 1;
                    l4 = (Long) aVarC.v(descriptor2, 0, P.a, l4);
                    remoteTextbook = remoteTextbook;
                    bool2 = bool2;
                    z2 = z;
                case 1:
                    z = z2;
                    str10 = (String) aVarC.v(descriptor2, 1, q0.a, str10);
                    i |= 2;
                    str3 = str11;
                    remoteTextbook = remoteTextbook;
                    str4 = str4;
                    l2 = l2;
                    z2 = z;
                case 2:
                    l = l2;
                    str3 = (String) aVarC.v(descriptor2, 2, q0.a, str11);
                    i |= 4;
                    str4 = str4;
                    l2 = l;
                case 3:
                    l = l2;
                    str4 = (String) aVarC.v(descriptor2, 3, q0.a, str4);
                    i |= 8;
                    str3 = str11;
                    l2 = l;
                case 4:
                    str = str4;
                    str5 = (String) aVarC.v(descriptor2, 4, q0.a, str5);
                    i |= 16;
                    str3 = str11;
                    str4 = str;
                case 5:
                    str = str4;
                    str6 = (String) aVarC.v(descriptor2, 5, q0.a, str6);
                    i |= 32;
                    str3 = str11;
                    str4 = str;
                case 6:
                    str = str4;
                    str7 = (String) aVarC.v(descriptor2, 6, q0.a, str7);
                    i |= 64;
                    str3 = str11;
                    str4 = str;
                case 7:
                    str = str4;
                    str8 = (String) aVarC.v(descriptor2, 7, q0.a, str8);
                    i |= 128;
                    str3 = str11;
                    str4 = str;
                case 8:
                    str = str4;
                    str9 = (String) aVarC.v(descriptor2, 8, q0.a, str9);
                    i |= 256;
                    str3 = str11;
                    str4 = str;
                case 9:
                    str = str4;
                    bool = (Boolean) aVarC.v(descriptor2, 9, C5053g.a, bool);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    str3 = str11;
                    str4 = str;
                case 10:
                    str = str4;
                    str2 = (String) aVarC.v(descriptor2, 10, q0.a, str2);
                    i |= 1024;
                    str3 = str11;
                    str4 = str;
                case 11:
                    str = str4;
                    remoteTextbook = (RemoteTextbook) aVarC.v(descriptor2, 11, RemoteTextbook$$serializer.INSTANCE, remoteTextbook);
                    i |= 2048;
                    str3 = str11;
                    str4 = str;
                case 12:
                    str = str4;
                    l3 = (Long) aVarC.v(descriptor2, 12, P.a, l3);
                    i |= 4096;
                    str3 = str11;
                    str4 = str;
                case 13:
                    str = str4;
                    l2 = (Long) aVarC.v(descriptor2, 13, P.a, l2);
                    i |= 8192;
                    str3 = str11;
                    str4 = str;
                case 14:
                    str = str4;
                    bool2 = (Boolean) aVarC.v(descriptor2, 14, C5053g.a, bool2);
                    i |= 16384;
                    str3 = str11;
                    str4 = str;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        RemoteTextbook remoteTextbook2 = remoteTextbook;
        Boolean bool3 = bool2;
        int i2 = i;
        Long l5 = l4;
        String str12 = str10;
        aVarC.b(descriptor2);
        return new RemoteTextbookExercise(i2, l5, str12, str3, str4, str5, str6, str7, str8, str9, bool, str2, remoteTextbook2, l3, l2, bool3);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteTextbookExercise value) {
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
        bVarC.s(descriptor2, 6, q0Var, value.g);
        bVarC.s(descriptor2, 7, q0Var, value.h);
        bVarC.s(descriptor2, 8, q0Var, value.i);
        C5053g c5053g = C5053g.a;
        bVarC.s(descriptor2, 9, c5053g, value.j);
        bVarC.s(descriptor2, 10, q0Var, value.k);
        bVarC.s(descriptor2, 11, RemoteTextbook$$serializer.INSTANCE, value.l);
        bVarC.s(descriptor2, 12, p, value.m);
        bVarC.s(descriptor2, 13, p, value.n);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.o;
        if (zD || bool != null) {
            bVarC.s(descriptor2, 14, c5053g, bool);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
