package com.quizlet.featuregate.features.folder;

import com.google.android.gms.internal.mlkit_vision_camera.I1;
import kotlin.coroutines.h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e {
    public final androidx.work.impl.model.c a;

    public e(androidx.work.impl.model.c userProperties, int i) {
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(userProperties, "userProperties");
                this.a = userProperties;
                break;
            default:
                Intrinsics.checkNotNullParameter(userProperties, "userProperties");
                this.a = userProperties;
                break;
        }
    }

    public Object a(h hVar) {
        return I1.b(com.google.android.gms.dynamite.d.e(this.a.u()), hVar);
    }
}
