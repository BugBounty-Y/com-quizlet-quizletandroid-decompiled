package assistantMode.refactored.modelTypes.relational;

import assistantMode.refactored.enums.g;
import assistantMode.refactored.enums.h;
import assistantMode.refactored.enums.m;
import assistantMode.refactored.enums.n;
import assistantMode.refactored.modelTypes.AudioValue;
import assistantMode.refactored.modelTypes.AudioValue$$serializer;
import assistantMode.refactored.modelTypes.DiagramShapeValue;
import assistantMode.refactored.modelTypes.DiagramShapeValue$$serializer;
import assistantMode.refactored.modelTypes.ImageValue;
import assistantMode.refactored.modelTypes.ImageValue$$serializer;
import assistantMode.refactored.modelTypes.TextValue;
import assistantMode.refactored.modelTypes.TextValue$$serializer;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
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
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class RelationalStudiableMediaConnection$$serializer implements D {

    @NotNull
    public static final RelationalStudiableMediaConnection$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RelationalStudiableMediaConnection$$serializer relationalStudiableMediaConnection$$serializer = new RelationalStudiableMediaConnection$$serializer();
        INSTANCE = relationalStudiableMediaConnection$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.modelTypes.relational.RelationalStudiableMediaConnection", relationalStudiableMediaConnection$$serializer, 7);
        pluginGeneratedSerialDescriptor.k("connectionType", false);
        pluginGeneratedSerialDescriptor.k("connectionModelId", false);
        pluginGeneratedSerialDescriptor.k("mediaType", false);
        pluginGeneratedSerialDescriptor.k("text", true);
        pluginGeneratedSerialDescriptor.k("audio", true);
        pluginGeneratedSerialDescriptor.k("image", true);
        pluginGeneratedSerialDescriptor.k(DBDiagramShape.TABLE_NAME, true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RelationalStudiableMediaConnection$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{m.f, P.a, g.f, R1.e(TextValue$$serializer.INSTANCE), R1.e(AudioValue$$serializer.INSTANCE), R1.e(ImageValue$$serializer.INSTANCE), R1.e(DiagramShapeValue$$serializer.INSTANCE)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RelationalStudiableMediaConnection deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        DiagramShapeValue diagramShapeValue = null;
        int i = 0;
        n nVar = null;
        h hVar = null;
        TextValue textValue = null;
        AudioValue audioValue = null;
        ImageValue imageValue = null;
        long j = 0;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    nVar = (n) aVarC.z(descriptor2, 0, m.f, nVar);
                    i |= 1;
                    break;
                case 1:
                    j = aVarC.j(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    hVar = (h) aVarC.z(descriptor2, 2, g.f, hVar);
                    i |= 4;
                    break;
                case 3:
                    textValue = (TextValue) aVarC.v(descriptor2, 3, TextValue$$serializer.INSTANCE, textValue);
                    i |= 8;
                    break;
                case 4:
                    audioValue = (AudioValue) aVarC.v(descriptor2, 4, AudioValue$$serializer.INSTANCE, audioValue);
                    i |= 16;
                    break;
                case 5:
                    imageValue = (ImageValue) aVarC.v(descriptor2, 5, ImageValue$$serializer.INSTANCE, imageValue);
                    i |= 32;
                    break;
                case 6:
                    diagramShapeValue = (DiagramShapeValue) aVarC.v(descriptor2, 6, DiagramShapeValue$$serializer.INSTANCE, diagramShapeValue);
                    i |= 64;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new RelationalStudiableMediaConnection(i, nVar, j, hVar, textValue, audioValue, imageValue, diagramShapeValue);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RelationalStudiableMediaConnection value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, m.f, value.a);
        bVarC.C(descriptor2, 1, value.b);
        bVarC.i(descriptor2, 2, g.f, value.c);
        boolean zD = bVarC.D(descriptor2);
        TextValue textValue = value.d;
        if (zD || textValue != null) {
            bVarC.s(descriptor2, 3, TextValue$$serializer.INSTANCE, textValue);
        }
        boolean zD2 = bVarC.D(descriptor2);
        AudioValue audioValue = value.e;
        if (zD2 || audioValue != null) {
            bVarC.s(descriptor2, 4, AudioValue$$serializer.INSTANCE, audioValue);
        }
        boolean zD3 = bVarC.D(descriptor2);
        ImageValue imageValue = value.f;
        if (zD3 || imageValue != null) {
            bVarC.s(descriptor2, 5, ImageValue$$serializer.INSTANCE, imageValue);
        }
        boolean zD4 = bVarC.D(descriptor2);
        DiagramShapeValue diagramShapeValue = value.g;
        if (zD4 || diagramShapeValue != null) {
            bVarC.s(descriptor2, 6, DiagramShapeValue$$serializer.INSTANCE, diagramShapeValue);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
