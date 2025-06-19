package com.quizlet.billing.client.provider;

import android.content.Context;
import com.android.billingclient.api.e;
import com.android.billingclient.api.k;
import com.quizlet.billing.manager.f;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class a implements k {
    public final Context a;
    public f b;

    public a(@NotNull Context appContext) {
        Intrinsics.checkNotNullParameter(appContext, "appContext");
        this.a = appContext;
    }

    @Override // com.android.billingclient.api.k
    public final void a(e result, List list) {
        Intrinsics.checkNotNullParameter(result, "result");
        f fVar = this.b;
        if (fVar != null) {
            fVar.a(result, list);
        }
    }
}
