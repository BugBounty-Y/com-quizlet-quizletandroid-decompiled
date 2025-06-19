package com.quizlet.shared.models.folders;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
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
public final class Folder$$serializer implements D {

    @NotNull
    public static final Folder$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        Folder$$serializer folder$$serializer = new Folder$$serializer();
        INSTANCE = folder$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("Folder", folder$$serializer, 9);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("user", false);
        pluginGeneratedSerialDescriptor.k("name", false);
        pluginGeneratedSerialDescriptor.k(OTUXParamsKeys.OT_UX_DESCRIPTION, false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k("numSets", false);
        pluginGeneratedSerialDescriptor.k("isHidden", false);
        pluginGeneratedSerialDescriptor.k("webUrl", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private Folder$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        KSerializer kSerializerE = R1.e(q0Var);
        P p = P.a;
        return new KSerializer[]{p, User$$serializer.INSTANCE, q0Var, q0Var, p, p, p, C5053g.a, kSerializerE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public Folder deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        String str = null;
        int i = 0;
        boolean zQ = false;
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        long j4 = 0;
        User user = null;
        String strR = null;
        String strR2 = null;
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
                    user = (User) aVarC.z(descriptor2, 1, User$$serializer.INSTANCE, user);
                    i |= 2;
                    break;
                case 2:
                    strR = aVarC.r(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    strR2 = aVarC.r(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    j2 = aVarC.j(descriptor2, 4);
                    i |= 16;
                    break;
                case 5:
                    j3 = aVarC.j(descriptor2, 5);
                    i |= 32;
                    break;
                case 6:
                    j4 = aVarC.j(descriptor2, 6);
                    i |= 64;
                    break;
                case 7:
                    zQ = aVarC.q(descriptor2, 7);
                    i |= 128;
                    break;
                case 8:
                    str = (String) aVarC.v(descriptor2, 8, q0.a, str);
                    i |= 256;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new Folder(i, j, user, strR, strR2, j2, j3, j4, zQ, str);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull Folder value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.c);
        bVarC.i(descriptor2, 1, User$$serializer.INSTANCE, value.d);
        bVarC.r(descriptor2, 2, value.e);
        bVarC.r(descriptor2, 3, value.f);
        bVarC.C(descriptor2, 4, value.g);
        bVarC.C(descriptor2, 5, value.h);
        bVarC.C(descriptor2, 6, value.i);
        bVarC.p(descriptor2, 7, value.j);
        bVarC.s(descriptor2, 8, q0.a, value.k);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
