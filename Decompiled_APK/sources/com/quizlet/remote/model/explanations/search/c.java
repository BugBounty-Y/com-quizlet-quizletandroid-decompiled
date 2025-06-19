package com.quizlet.remote.model.explanations.search;

import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.B1;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements com.quizlet.remote.mapper.base.b {
    @Override // com.quizlet.remote.mapper.base.a
    public final Object c(Object obj) {
        RemoteSearchSuggestion remote = (RemoteSearchSuggestion) obj;
        Intrinsics.checkNotNullParameter(remote, "remote");
        return new B1(remote.a, remote.b);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final List e(List list) {
        return T.f(this, list);
    }

    @Override // com.quizlet.remote.mapper.base.c
    public final Object h(Object obj) {
        B1 data = (B1) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        return new RemoteSearchSuggestion(data.a, data.b);
    }
}
