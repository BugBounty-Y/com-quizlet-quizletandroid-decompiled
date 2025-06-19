package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z5;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes2.dex */
public abstract class S1 {
    public static final void a(com.quizlet.assembly.compose.modals.x state, androidx.compose.ui.n nVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-480562553);
        int i2 = i | (c0814p.h(state) ? 4 : 2) | 48 | (c0814p.h(function0) ? 256 : 128) | (c0814p.h(function02) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            int i3 = (i2 & 14) | 8;
            int i4 = i2 << 9;
            Z5.b(state, AbstractC3106b5.d(c0814p, R.string.practice_test_signup_wall_title), AbstractC3106b5.d(c0814p, R.string.practice_test_signup_wall_signup_button), AbstractC3106b5.d(c0814p, R.string.practice_test_signup_wall_subtitle), AbstractC3106b5.d(c0814p, R.string.practice_test_signup_wall_login_button), function0, function02, c0814p, (i4 & 3670016) | i3 | (458752 & i4) | 12582912);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(state, nVar2, function0, function02, i);
        }
    }

    public static final kotlin.reflect.c b(SerialDescriptor serialDescriptor) {
        Intrinsics.checkNotNullParameter(serialDescriptor, "<this>");
        if (serialDescriptor instanceof kotlinx.serialization.descriptors.b) {
            return ((kotlinx.serialization.descriptors.b) serialDescriptor).b;
        }
        if (serialDescriptor instanceof kotlinx.serialization.internal.k0) {
            return b(((kotlinx.serialization.internal.k0) serialDescriptor).a);
        }
        return null;
    }

    public static final androidx.paging.compose.a c(androidx.paging.compose.d dVar, Function1 function1) {
        Intrinsics.checkNotNullParameter(dVar, "<this>");
        return new androidx.paging.compose.a(dVar, function1);
    }
}
