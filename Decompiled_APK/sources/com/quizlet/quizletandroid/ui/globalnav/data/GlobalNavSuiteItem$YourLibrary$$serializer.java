package com.quizlet.quizletandroid.ui.globalnav.data;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$YourLibrary;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public /* synthetic */ class GlobalNavSuiteItem$YourLibrary$$serializer implements D {
    public static final int $stable;

    @NotNull
    public static final GlobalNavSuiteItem$YourLibrary$$serializer INSTANCE;

    @NotNull
    private static final SerialDescriptor descriptor;

    static {
        GlobalNavSuiteItem$YourLibrary$$serializer globalNavSuiteItem$YourLibrary$$serializer = new GlobalNavSuiteItem$YourLibrary$$serializer();
        INSTANCE = globalNavSuiteItem$YourLibrary$$serializer;
        $stable = 8;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem.YourLibrary", globalNavSuiteItem$YourLibrary$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("label", false);
        pluginGeneratedSerialDescriptor.k("tab", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private GlobalNavSuiteItem$YourLibrary$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public final KSerializer[] childSerializers() {
        return new KSerializer[]{K.a, R1.e(q0.a)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final GlobalNavSuiteItem$YourLibrary deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor serialDescriptor = descriptor;
        kotlinx.serialization.encoding.a aVarC = decoder.c(serialDescriptor);
        String str = null;
        boolean z = true;
        int i = 0;
        int iN = 0;
        while (z) {
            int iT = aVarC.t(serialDescriptor);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                iN = aVarC.n(serialDescriptor, 0);
                i |= 1;
            } else {
                if (iT != 1) {
                    throw new UnknownFieldException(iT);
                }
                str = (String) aVarC.v(serialDescriptor, 1, q0.a, str);
                i |= 2;
            }
        }
        aVarC.b(serialDescriptor);
        return new GlobalNavSuiteItem$YourLibrary(i, iN, str);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(@NotNull Encoder encoder, @NotNull GlobalNavSuiteItem$YourLibrary value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor serialDescriptor = descriptor;
        kotlinx.serialization.encoding.b bVarC = encoder.c(serialDescriptor);
        GlobalNavSuiteItem$YourLibrary.Companion companion = GlobalNavSuiteItem$YourLibrary.Companion;
        bVarC.l(0, value.a, serialDescriptor);
        boolean zD = bVarC.D(serialDescriptor);
        String str = value.c;
        if (zD || str != null) {
            bVarC.s(serialDescriptor, 1, q0.a, str);
        }
        bVarC.b(serialDescriptor);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public /* bridge */ /* synthetic */ KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
