package com.quizlet.remote.model.base;

import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.J0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements com.quizlet.remote.mapper.base.b {
    public static J0 a(PagingInfo remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        int i = remote.a;
        int i2 = remote.d;
        return new J0(i, remote.b, remote.c, i2);
    }

    public static PagingInfo b(J0 data) {
        Intrinsics.checkNotNullParameter(data, "data");
        return new PagingInfo(data.a, data.b, data.d, data.c);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final /* bridge */ /* synthetic */ Object c(Object obj) {
        return a((PagingInfo) obj);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final List e(List list) {
        return T.f(this, list);
    }

    @Override // com.quizlet.remote.mapper.base.c
    public final /* bridge */ /* synthetic */ Object h(Object obj) {
        return b((J0) obj);
    }
}
