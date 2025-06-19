package com.quizlet.shared.models.api.grading;

import com.amazon.device.ads.DtbDeviceData;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.shared.enums.k;
import com.quizlet.shared.enums.l;
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
import kotlinx.serialization.internal.C5067v;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class LongtextGradingResult$$serializer implements D {

    @NotNull
    public static final LongtextGradingResult$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        LongtextGradingResult$$serializer longtextGradingResult$$serializer = new LongtextGradingResult$$serializer();
        INSTANCE = longtextGradingResult$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.grading.LongtextGradingResult", longtextGradingResult$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("grade", false);
        pluginGeneratedSerialDescriptor.k(DBSessionFields.Names.SCORE, false);
        pluginGeneratedSerialDescriptor.k(DtbDeviceData.DEVICE_DATA_MODEL_KEY, false);
        pluginGeneratedSerialDescriptor.k("cnnScore", true);
        pluginGeneratedSerialDescriptor.k("missing", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private LongtextGradingResult$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        C5067v c5067v = C5067v.a;
        q0 q0Var = q0.a;
        return new KSerializer[]{k.f, c5067v, q0Var, R1.e(c5067v), R1.e(q0Var)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public LongtextGradingResult deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        int i = 0;
        l lVar = null;
        String strR = null;
        Double d = null;
        String str = null;
        double dY = 0.0d;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                lVar = (l) aVarC.z(descriptor2, 0, k.f, lVar);
                i |= 1;
            } else if (iT == 1) {
                dY = aVarC.y(descriptor2, 1);
                i |= 2;
            } else if (iT == 2) {
                strR = aVarC.r(descriptor2, 2);
                i |= 4;
            } else if (iT == 3) {
                d = (Double) aVarC.v(descriptor2, 3, C5067v.a, d);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                str = (String) aVarC.v(descriptor2, 4, q0.a, str);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new LongtextGradingResult(i, lVar, dY, strR, d, str);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull LongtextGradingResult value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, k.f, value.a);
        bVarC.A(descriptor2, 1, value.b);
        bVarC.r(descriptor2, 2, value.c);
        boolean zD = bVarC.D(descriptor2);
        Double d = value.d;
        if (zD || d != null) {
            bVarC.s(descriptor2, 3, C5067v.a, d);
        }
        boolean zD2 = bVarC.D(descriptor2);
        String str = value.e;
        if (zD2 || str != null) {
            bVarC.s(descriptor2, 4, q0.a, str);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
