package assistantMode.types;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
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
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class Session$$serializer implements kotlinx.serialization.internal.D {

    @NotNull
    public static final Session$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        Session$$serializer session$$serializer = new Session$$serializer();
        INSTANCE = session$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.types.Session", session$$serializer, 13);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("personId", false);
        pluginGeneratedSerialDescriptor.k(DBSessionFields.Names.ITEM_ID, false);
        pluginGeneratedSerialDescriptor.k(DBSessionFields.Names.ITEM_TYPE, false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("endedTimestamp", false);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.USER_UPGRADE_TYPE, false);
        pluginGeneratedSerialDescriptor.k(DBSessionFields.Names.SCORE, false);
        pluginGeneratedSerialDescriptor.k("hidden", false);
        pluginGeneratedSerialDescriptor.k(DBSessionFields.Names.SELECTED_TERMS_ONLY, false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k("_folderId", false);
        pluginGeneratedSerialDescriptor.k("_setId", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private Session$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        P p = P.a;
        KSerializer kSerializerE = R1.e(p);
        KSerializer kSerializerE2 = R1.e(p);
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{p, p, p, p, p, p, p, p, c5053g, c5053g, p, kSerializerE, kSerializerE2};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public Session deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        Long l = null;
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        long j4 = 0;
        long j5 = 0;
        long j6 = 0;
        long j7 = 0;
        long j8 = 0;
        long j9 = 0;
        Long l2 = null;
        int i = 0;
        boolean zQ = false;
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
                    j2 = aVarC.j(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    j3 = aVarC.j(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    j4 = aVarC.j(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    j5 = aVarC.j(descriptor2, 4);
                    i |= 16;
                    break;
                case 5:
                    j6 = aVarC.j(descriptor2, 5);
                    i |= 32;
                    break;
                case 6:
                    j7 = aVarC.j(descriptor2, 6);
                    i |= 64;
                    break;
                case 7:
                    j8 = aVarC.j(descriptor2, 7);
                    i |= 128;
                    break;
                case 8:
                    zQ = aVarC.q(descriptor2, 8);
                    i |= 256;
                    break;
                case 9:
                    zQ2 = aVarC.q(descriptor2, 9);
                    i |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
                    break;
                case 10:
                    j9 = aVarC.j(descriptor2, 10);
                    i |= 1024;
                    break;
                case 11:
                    l = (Long) aVarC.v(descriptor2, 11, P.a, l);
                    i |= 2048;
                    break;
                case 12:
                    l2 = (Long) aVarC.v(descriptor2, 12, P.a, l2);
                    i |= 4096;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new Session(i, j, j2, j3, j4, j5, j6, j7, j8, zQ, zQ2, j9, l, l2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull Session value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.a);
        bVarC.C(descriptor2, 1, value.b);
        bVarC.C(descriptor2, 2, value.c);
        bVarC.C(descriptor2, 3, value.d);
        bVarC.C(descriptor2, 4, value.e);
        bVarC.C(descriptor2, 5, value.f);
        bVarC.C(descriptor2, 6, value.g);
        bVarC.C(descriptor2, 7, value.h);
        bVarC.p(descriptor2, 8, value.i);
        bVarC.p(descriptor2, 9, value.j);
        bVarC.C(descriptor2, 10, value.k);
        P p = P.a;
        bVarC.s(descriptor2, 11, p, value.l);
        bVarC.s(descriptor2, 12, p, value.m);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
