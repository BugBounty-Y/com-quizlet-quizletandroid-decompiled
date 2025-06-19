package com.quizlet.quizletandroid.ui.globalnav.data;

import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$FreeTrial;
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
public /* synthetic */ class GlobalNavSuiteItem$FreeTrial$$serializer implements D {
    public static final int $stable;

    @NotNull
    public static final GlobalNavSuiteItem$FreeTrial$$serializer INSTANCE;

    @NotNull
    private static final SerialDescriptor descriptor;

    static {
        GlobalNavSuiteItem$FreeTrial$$serializer globalNavSuiteItem$FreeTrial$$serializer = new GlobalNavSuiteItem$FreeTrial$$serializer();
        INSTANCE = globalNavSuiteItem$FreeTrial$$serializer;
        $stable = 8;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem.FreeTrial", globalNavSuiteItem$FreeTrial$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("label", false);
        pluginGeneratedSerialDescriptor.k("upgradeSource", false);
        pluginGeneratedSerialDescriptor.k("navigationSource", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private GlobalNavSuiteItem$FreeTrial$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public final KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        return new KSerializer[]{K.a, q0Var, q0Var};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final GlobalNavSuiteItem$FreeTrial deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor serialDescriptor = descriptor;
        kotlinx.serialization.encoding.a aVarC = decoder.c(serialDescriptor);
        String strR = null;
        boolean z = true;
        int i = 0;
        int iN = 0;
        String strR2 = null;
        while (z) {
            int iT = aVarC.t(serialDescriptor);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                iN = aVarC.n(serialDescriptor, 0);
                i |= 1;
            } else if (iT == 1) {
                strR = aVarC.r(serialDescriptor, 1);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                strR2 = aVarC.r(serialDescriptor, 2);
                i |= 4;
            }
        }
        aVarC.b(serialDescriptor);
        return new GlobalNavSuiteItem$FreeTrial(strR, i, strR2, iN);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(@NotNull Encoder encoder, @NotNull GlobalNavSuiteItem$FreeTrial value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor serialDescriptor = descriptor;
        kotlinx.serialization.encoding.b bVarC = encoder.c(serialDescriptor);
        GlobalNavSuiteItem$FreeTrial.Companion companion = GlobalNavSuiteItem$FreeTrial.Companion;
        bVarC.l(0, value.a, serialDescriptor);
        bVarC.r(serialDescriptor, 1, value.c);
        bVarC.r(serialDescriptor, 2, value.d);
        bVarC.b(serialDescriptor);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public /* bridge */ /* synthetic */ KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
