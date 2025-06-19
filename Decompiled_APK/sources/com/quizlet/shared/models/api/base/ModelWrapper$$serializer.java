package com.quizlet.shared.models.api.base;

import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.models.api.base.ModelWrapper;
import java.util.List;
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
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class ModelWrapper$$serializer implements D {

    @NotNull
    public static final ModelWrapper$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        ModelWrapper$$serializer modelWrapper$$serializer = new ModelWrapper$$serializer();
        INSTANCE = modelWrapper$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.base.ModelWrapper", modelWrapper$$serializer, 12);
        pluginGeneratedSerialDescriptor.k("artifact", true);
        pluginGeneratedSerialDescriptor.k("explanationQuestion", true);
        pluginGeneratedSerialDescriptor.k("folder", true);
        pluginGeneratedSerialDescriptor.k("folderStudyMaterial", true);
        pluginGeneratedSerialDescriptor.k("magicNote", true);
        pluginGeneratedSerialDescriptor.k("set", true);
        pluginGeneratedSerialDescriptor.k("studiableMetadata", true);
        pluginGeneratedSerialDescriptor.k("studyNote", true);
        pluginGeneratedSerialDescriptor.k("term", true);
        pluginGeneratedSerialDescriptor.k("textbook", true);
        pluginGeneratedSerialDescriptor.k("textbookExercise", true);
        pluginGeneratedSerialDescriptor.k("user", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private ModelWrapper$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = ModelWrapper.m;
        return new KSerializer[]{R1.e(kSerializerArr[0]), R1.e(kSerializerArr[1]), R1.e(kSerializerArr[2]), R1.e(kSerializerArr[3]), R1.e(kSerializerArr[4]), R1.e(kSerializerArr[5]), R1.e(kSerializerArr[6]), R1.e(kSerializerArr[7]), R1.e(kSerializerArr[8]), R1.e(kSerializerArr[9]), R1.e(kSerializerArr[10]), R1.e(kSerializerArr[11])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public ModelWrapper deserialize(@NotNull Decoder decoder) {
        List list;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = ModelWrapper.m;
        List list2 = null;
        List list3 = null;
        List list4 = null;
        List list5 = null;
        List list6 = null;
        List list7 = null;
        List list8 = null;
        List list9 = null;
        List list10 = null;
        List list11 = null;
        List list12 = null;
        List list13 = null;
        int i = 0;
        boolean z = true;
        int i2 = 1;
        while (z) {
            KSerializer[] kSerializerArr2 = kSerializerArr;
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    kSerializerArr = kSerializerArr2;
                    i2 = 1;
                    list6 = list6;
                    i = i;
                    continue;
                case 0:
                    i |= 1;
                    i2 = 1;
                    list6 = (List) aVarC.v(descriptor2, 0, kSerializerArr2[0], list6);
                    kSerializerArr = kSerializerArr2;
                    continue;
                case 1:
                    list = list6;
                    list7 = (List) aVarC.v(descriptor2, i2, kSerializerArr2[i2], list7);
                    i |= 2;
                    break;
                case 2:
                    list = list6;
                    list8 = (List) aVarC.v(descriptor2, 2, kSerializerArr2[2], list8);
                    i |= 4;
                    break;
                case 3:
                    list = list6;
                    list9 = (List) aVarC.v(descriptor2, 3, kSerializerArr2[3], list9);
                    i |= 8;
                    break;
                case 4:
                    list = list6;
                    list10 = (List) aVarC.v(descriptor2, 4, kSerializerArr2[4], list10);
                    i |= 16;
                    break;
                case 5:
                    list = list6;
                    list11 = (List) aVarC.v(descriptor2, 5, kSerializerArr2[5], list11);
                    i |= 32;
                    break;
                case 6:
                    list = list6;
                    list12 = (List) aVarC.v(descriptor2, 6, kSerializerArr2[6], list12);
                    i |= 64;
                    break;
                case 7:
                    list = list6;
                    list13 = (List) aVarC.v(descriptor2, 7, kSerializerArr2[7], list13);
                    i |= 128;
                    break;
                case 8:
                    list = list6;
                    list2 = (List) aVarC.v(descriptor2, 8, kSerializerArr2[8], list2);
                    i |= 256;
                    break;
                case 9:
                    list = list6;
                    list4 = (List) aVarC.v(descriptor2, 9, kSerializerArr2[9], list4);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    break;
                case 10:
                    list = list6;
                    list5 = (List) aVarC.v(descriptor2, 10, kSerializerArr2[10], list5);
                    i |= 1024;
                    break;
                case 11:
                    list = list6;
                    list3 = (List) aVarC.v(descriptor2, 11, kSerializerArr2[11], list3);
                    i |= 2048;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
            kSerializerArr = kSerializerArr2;
            list6 = list;
        }
        aVarC.b(descriptor2);
        return new ModelWrapper(i, list6, list7, list8, list9, list10, list11, list12, list13, list2, list4, list5, list3);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull ModelWrapper value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        ModelWrapper.Companion companion = ModelWrapper.Companion;
        boolean zD = bVarC.D(descriptor2);
        KSerializer[] kSerializerArr = ModelWrapper.m;
        if (zD || value.a != null) {
            bVarC.s(descriptor2, 0, kSerializerArr[0], value.a);
        }
        if (bVarC.D(descriptor2) || value.b != null) {
            bVarC.s(descriptor2, 1, kSerializerArr[1], value.b);
        }
        if (bVarC.D(descriptor2) || value.c != null) {
            bVarC.s(descriptor2, 2, kSerializerArr[2], value.c);
        }
        if (bVarC.D(descriptor2) || value.d != null) {
            bVarC.s(descriptor2, 3, kSerializerArr[3], value.d);
        }
        if (bVarC.D(descriptor2) || value.e != null) {
            bVarC.s(descriptor2, 4, kSerializerArr[4], value.e);
        }
        if (bVarC.D(descriptor2) || value.f != null) {
            bVarC.s(descriptor2, 5, kSerializerArr[5], value.f);
        }
        if (bVarC.D(descriptor2) || value.g != null) {
            bVarC.s(descriptor2, 6, kSerializerArr[6], value.g);
        }
        if (bVarC.D(descriptor2) || value.h != null) {
            bVarC.s(descriptor2, 7, kSerializerArr[7], value.h);
        }
        if (bVarC.D(descriptor2) || value.i != null) {
            bVarC.s(descriptor2, 8, kSerializerArr[8], value.i);
        }
        if (bVarC.D(descriptor2) || value.j != null) {
            bVarC.s(descriptor2, 9, kSerializerArr[9], value.j);
        }
        if (bVarC.D(descriptor2) || value.k != null) {
            bVarC.s(descriptor2, 10, kSerializerArr[10], value.k);
        }
        if (bVarC.D(descriptor2) || value.l != null) {
            bVarC.s(descriptor2, 11, kSerializerArr[11], value.l);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
