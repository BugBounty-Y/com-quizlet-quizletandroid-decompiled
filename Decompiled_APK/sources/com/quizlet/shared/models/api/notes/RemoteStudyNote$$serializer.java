package com.quizlet.shared.models.api.notes;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.shared.models.api.user.RemoteUser;
import com.quizlet.shared.models.api.user.RemoteUser$$serializer;
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
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class RemoteStudyNote$$serializer implements D {

    @NotNull
    public static final RemoteStudyNote$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteStudyNote$$serializer remoteStudyNote$$serializer = new RemoteStudyNote$$serializer();
        INSTANCE = remoteStudyNote$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.notes.RemoteStudyNote", remoteStudyNote$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("uuid", false);
        pluginGeneratedSerialDescriptor.k("title", false);
        pluginGeneratedSerialDescriptor.k(AssociationNames.CREATOR, false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        pluginGeneratedSerialDescriptor.k("redirectToWeb", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteStudyNote$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        KSerializer kSerializerE = R1.e(q0Var);
        KSerializer kSerializerE2 = R1.e(q0Var);
        KSerializer kSerializerE3 = R1.e(RemoteUser$$serializer.INSTANCE);
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{kSerializerE, kSerializerE2, kSerializerE3, R1.e(c5053g), R1.e(c5053g)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteStudyNote deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        String str = null;
        String str2 = null;
        RemoteUser remoteUser = null;
        Boolean bool = null;
        Boolean bool2 = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                str = (String) aVarC.v(descriptor2, 0, q0.a, str);
                i |= 1;
            } else if (iT == 1) {
                str2 = (String) aVarC.v(descriptor2, 1, q0.a, str2);
                i |= 2;
            } else if (iT == 2) {
                remoteUser = (RemoteUser) aVarC.v(descriptor2, 2, RemoteUser$$serializer.INSTANCE, remoteUser);
                i |= 4;
            } else if (iT == 3) {
                bool = (Boolean) aVarC.v(descriptor2, 3, C5053g.a, bool);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                bool2 = (Boolean) aVarC.v(descriptor2, 4, C5053g.a, bool2);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new RemoteStudyNote(i, str, str2, remoteUser, bool, bool2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteStudyNote value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        q0 q0Var = q0.a;
        bVarC.s(descriptor2, 0, q0Var, value.a);
        bVarC.s(descriptor2, 1, q0Var, value.b);
        bVarC.s(descriptor2, 2, RemoteUser$$serializer.INSTANCE, value.c);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.d;
        if (zD || bool != null) {
            bVarC.s(descriptor2, 3, C5053g.a, bool);
        }
        boolean zD2 = bVarC.D(descriptor2);
        Boolean bool2 = value.e;
        if (zD2 || bool2 != null) {
            bVarC.s(descriptor2, 4, C5053g.a, bool2);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
