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
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class TextbookExercise$$serializer implements D {

    @NotNull
    public static final TextbookExercise$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        TextbookExercise$$serializer textbookExercise$$serializer = new TextbookExercise$$serializer();
        INSTANCE = textbookExercise$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("TextbookExercise", textbookExercise$$serializer, 13);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("exerciseName", false);
        pluginGeneratedSerialDescriptor.k("mediaExerciseId", false);
        pluginGeneratedSerialDescriptor.k("chapterName", false);
        pluginGeneratedSerialDescriptor.k("chapterTitle", false);
        pluginGeneratedSerialDescriptor.k("groupTitle", false);
        pluginGeneratedSerialDescriptor.k("isPremium", false);
        pluginGeneratedSerialDescriptor.k("sectionName", false);
        pluginGeneratedSerialDescriptor.k("sectionTitle", false);
        pluginGeneratedSerialDescriptor.k("pageNumber", false);
        pluginGeneratedSerialDescriptor.k("webUrl", false);
        pluginGeneratedSerialDescriptor.k("textbook", false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private TextbookExercise$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        KSerializer kSerializerE = R1.e(q0Var);
        KSerializer kSerializerE2 = R1.e(q0Var);
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{P.a, q0Var, q0Var, q0Var, kSerializerE, kSerializerE2, c5053g, R1.e(q0Var), R1.e(q0Var), R1.e(q0Var), R1.e(q0Var), Textbook$$serializer.INSTANCE, R1.e(c5053g)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public TextbookExercise deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        String str = null;
        long j = 0;
        Boolean bool = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        Textbook textbook = null;
        String strR = null;
        String strR2 = null;
        String strR3 = null;
        String str5 = null;
        String str6 = null;
        int i = 0;
        boolean z = true;
        boolean zQ = false;
        while (true) {
            long j2 = j;
            if (!z) {
                aVarC.b(descriptor2);
                return new TextbookExercise(i, j, strR, strR2, strR3, str5, str6, zQ, str, str2, str3, str4, textbook, bool);
            }
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    j2 = aVarC.j(descriptor2, 0);
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
                    str5 = (String) aVarC.v(descriptor2, 4, q0.a, str5);
                    i |= 16;
                    break;
                case 5:
                    str6 = (String) aVarC.v(descriptor2, 5, q0.a, str6);
                    i |= 32;
                    break;
                case 6:
                    zQ = aVarC.q(descriptor2, 6);
                    i |= 64;
                    break;
                case 7:
                    str = (String) aVarC.v(descriptor2, 7, q0.a, str);
                    i |= 128;
                    break;
                case 8:
                    str2 = (String) aVarC.v(descriptor2, 8, q0.a, str2);
                    i |= 256;
                    break;
                case 9:
                    str3 = (String) aVarC.v(descriptor2, 9, q0.a, str3);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    break;
                case 10:
                    str4 = (String) aVarC.v(descriptor2, 10, q0.a, str4);
                    i |= 1024;
                    break;
                case 11:
                    textbook = (Textbook) aVarC.z(descriptor2, 11, Textbook$$serializer.INSTANCE, textbook);
                    i |= 2048;
                    break;
                case 12:
                    bool = (Boolean) aVarC.v(descriptor2, 12, C5053g.a, bool);
                    i |= 4096;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
            j = j2;
        }
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull TextbookExercise value) {
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
        bVarC.s(descriptor2, 7, q0Var, value.i);
        bVarC.s(descriptor2, 8, q0Var, value.j);
        bVarC.s(descriptor2, 9, q0Var, value.k);
        bVarC.s(descriptor2, 10, q0Var, value.l);
        bVarC.i(descriptor2, 11, Textbook$$serializer.INSTANCE, value.m);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.n;
        if (zD || bool != null) {
            bVarC.s(descriptor2, 12, C5053g.a, bool);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
