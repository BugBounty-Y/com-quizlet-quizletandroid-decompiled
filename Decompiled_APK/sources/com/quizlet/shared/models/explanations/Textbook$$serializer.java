package com.quizlet.shared.models.explanations;

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
public final class Textbook$$serializer implements D {

    @NotNull
    public static final Textbook$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        Textbook$$serializer textbook$$serializer = new Textbook$$serializer();
        INSTANCE = textbook$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("Textbook", textbook$$serializer, 12);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("isbn", false);
        pluginGeneratedSerialDescriptor.k("title", false);
        pluginGeneratedSerialDescriptor.k("authors", false);
        pluginGeneratedSerialDescriptor.k("imageUrl", false);
        pluginGeneratedSerialDescriptor.k("imageThumbnailUrl", false);
        pluginGeneratedSerialDescriptor.k("isPremium", false);
        pluginGeneratedSerialDescriptor.k("edition", false);
        pluginGeneratedSerialDescriptor.k("verifiedSolutionCount", false);
        pluginGeneratedSerialDescriptor.k("hasSolutions", false);
        pluginGeneratedSerialDescriptor.k("webUrl", false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private Textbook$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        KSerializer kSerializerE = R1.e(q0Var);
        KSerializer kSerializerE2 = R1.e(q0Var);
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{P.a, q0Var, q0Var, q0Var, kSerializerE, kSerializerE2, c5053g, q0Var, K.a, c5053g, R1.e(q0Var), R1.e(c5053g)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public Textbook deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        String str = null;
        long j = 0;
        Boolean bool = null;
        String strR = null;
        String strR2 = null;
        String strR3 = null;
        String str2 = null;
        String str3 = null;
        String strR4 = null;
        int i = 0;
        boolean zQ = false;
        int iN = 0;
        boolean zQ2 = false;
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
                    strR = aVarC.r(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    strR2 = aVarC.r(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    strR3 = aVarC.r(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    str2 = (String) aVarC.v(descriptor2, 4, q0.a, str2);
                    i |= 16;
                    break;
                case 5:
                    str3 = (String) aVarC.v(descriptor2, 5, q0.a, str3);
                    i |= 32;
                    break;
                case 6:
                    zQ = aVarC.q(descriptor2, 6);
                    i |= 64;
                    break;
                case 7:
                    strR4 = aVarC.r(descriptor2, 7);
                    i |= 128;
                    break;
                case 8:
                    iN = aVarC.n(descriptor2, 8);
                    i |= 256;
                    break;
                case 9:
                    zQ2 = aVarC.q(descriptor2, 9);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    break;
                case 10:
                    str = (String) aVarC.v(descriptor2, 10, q0.a, str);
                    i |= 1024;
                    break;
                case 11:
                    bool = (Boolean) aVarC.v(descriptor2, 11, C5053g.a, bool);
                    i |= 2048;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new Textbook(i, j, strR, strR2, strR3, str2, str3, zQ, strR4, iN, zQ2, str, bool);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull Textbook value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.b);
        bVarC.r(descriptor2, 1, value.c);
        bVarC.r(descriptor2, 2, value.d);
        bVarC.r(descriptor2, 3, value.e);
        q0 q0Var = q0.a;
        bVarC.s(descriptor2, 4, q0Var, value.f);
        bVarC.s(descriptor2, 5, q0Var, value.g);
        bVarC.p(descriptor2, 6, value.h);
        bVarC.r(descriptor2, 7, value.i);
        bVarC.l(8, value.j, descriptor2);
        bVarC.p(descriptor2, 9, value.k);
        bVarC.s(descriptor2, 10, q0Var, value.l);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.m;
        if (zD || bool != null) {
            bVarC.s(descriptor2, 11, C5053g.a, bool);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
