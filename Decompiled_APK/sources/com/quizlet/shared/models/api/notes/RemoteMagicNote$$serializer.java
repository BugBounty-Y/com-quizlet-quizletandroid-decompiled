package com.quizlet.shared.models.api.notes;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.models.api.notes.RemoteMagicNote;
import java.util.List;
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
public final class RemoteMagicNote$$serializer implements D {

    @NotNull
    public static final RemoteMagicNote$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteMagicNote$$serializer remoteMagicNote$$serializer = new RemoteMagicNote$$serializer();
        INSTANCE = remoteMagicNote$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.notes.RemoteMagicNote", remoteMagicNote$$serializer, 10);
        pluginGeneratedSerialDescriptor.k("uuid", false);
        pluginGeneratedSerialDescriptor.k("userId", false);
        pluginGeneratedSerialDescriptor.k("documentType", false);
        pluginGeneratedSerialDescriptor.k("private", false);
        pluginGeneratedSerialDescriptor.k("language", false);
        pluginGeneratedSerialDescriptor.k("extractedText", false);
        pluginGeneratedSerialDescriptor.k("createdAt", false);
        pluginGeneratedSerialDescriptor.k("artifactUuids", false);
        pluginGeneratedSerialDescriptor.k("userModifiedAt", false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteMagicNote$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = RemoteMagicNote.k;
        q0 q0Var = q0.a;
        KSerializer kSerializerE = R1.e(q0Var);
        KSerializer kSerializerE2 = R1.e(P.a);
        KSerializer kSerializerE3 = R1.e(q0Var);
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{kSerializerE, kSerializerE2, kSerializerE3, R1.e(c5053g), R1.e(q0Var), R1.e(q0Var), R1.e(q0Var), R1.e(kSerializerArr[7]), R1.e(q0Var), R1.e(c5053g)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteMagicNote deserialize(@NotNull Decoder decoder) {
        KSerializer[] kSerializerArr;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr2 = RemoteMagicNote.k;
        String str = null;
        Boolean bool = null;
        String str2 = null;
        Long l = null;
        String str3 = null;
        Boolean bool2 = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        List list = null;
        int i = 0;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    continue;
                case 0:
                    kSerializerArr = kSerializerArr2;
                    str2 = (String) aVarC.v(descriptor2, 0, q0.a, str2);
                    i |= 1;
                    break;
                case 1:
                    kSerializerArr = kSerializerArr2;
                    l = (Long) aVarC.v(descriptor2, 1, P.a, l);
                    i |= 2;
                    break;
                case 2:
                    kSerializerArr = kSerializerArr2;
                    str3 = (String) aVarC.v(descriptor2, 2, q0.a, str3);
                    i |= 4;
                    break;
                case 3:
                    kSerializerArr = kSerializerArr2;
                    bool2 = (Boolean) aVarC.v(descriptor2, 3, C5053g.a, bool2);
                    i |= 8;
                    break;
                case 4:
                    kSerializerArr = kSerializerArr2;
                    str4 = (String) aVarC.v(descriptor2, 4, q0.a, str4);
                    i |= 16;
                    break;
                case 5:
                    kSerializerArr = kSerializerArr2;
                    str5 = (String) aVarC.v(descriptor2, 5, q0.a, str5);
                    i |= 32;
                    break;
                case 6:
                    kSerializerArr = kSerializerArr2;
                    str6 = (String) aVarC.v(descriptor2, 6, q0.a, str6);
                    i |= 64;
                    break;
                case 7:
                    kSerializerArr = kSerializerArr2;
                    list = (List) aVarC.v(descriptor2, 7, kSerializerArr[7], list);
                    i |= 128;
                    break;
                case 8:
                    kSerializerArr = kSerializerArr2;
                    str = (String) aVarC.v(descriptor2, 8, q0.a, str);
                    i |= 256;
                    break;
                case 9:
                    kSerializerArr = kSerializerArr2;
                    bool = (Boolean) aVarC.v(descriptor2, 9, C5053g.a, bool);
                    i |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
            kSerializerArr2 = kSerializerArr;
        }
        aVarC.b(descriptor2);
        return new RemoteMagicNote(i, str2, l, str3, bool2, str4, str5, str6, list, str, bool);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteMagicNote value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        RemoteMagicNote.Companion companion = RemoteMagicNote.Companion;
        q0 q0Var = q0.a;
        bVarC.s(descriptor2, 0, q0Var, value.a);
        bVarC.s(descriptor2, 1, P.a, value.b);
        bVarC.s(descriptor2, 2, q0Var, value.c);
        C5053g c5053g = C5053g.a;
        bVarC.s(descriptor2, 3, c5053g, value.d);
        bVarC.s(descriptor2, 4, q0Var, value.e);
        bVarC.s(descriptor2, 5, q0Var, value.f);
        bVarC.s(descriptor2, 6, q0Var, value.g);
        bVarC.s(descriptor2, 7, RemoteMagicNote.k[7], value.h);
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
