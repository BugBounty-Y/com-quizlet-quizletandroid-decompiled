package com.quizlet.remote.model.progress;

import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.C4127f1;
import com.quizlet.generated.enums.F1;
import com.quizlet.generated.enums.G1;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.remote.mapper.base.b {
    @Override // com.quizlet.remote.mapper.base.a
    public final Object c(Object obj) {
        RemoteProgressReset remote = (RemoteProgressReset) obj;
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        G1.Companion.getClass();
        return new C4127f1(j, remote.b, F1.a(remote.c), remote.d);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final List e(List list) {
        return T.f(this, list);
    }

    @Override // com.quizlet.remote.mapper.base.c
    public final Object h(Object obj) {
        C4127f1 data = (C4127f1) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        return new RemoteProgressReset(data.a, data.b, data.c.b(), data.d);
    }
}
