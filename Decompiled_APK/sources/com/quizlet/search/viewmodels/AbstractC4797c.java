package com.quizlet.search.viewmodels;

import androidx.lifecycle.w0;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.generated.enums.K0;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* renamed from: com.quizlet.search.viewmodels.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4797c extends w0 {
    public final SearchEventLogger b;
    public InterfaceC4992i c;
    public String d;
    public boolean e;
    public boolean f;
    public final s0 g;

    public AbstractC4797c(SearchEventLogger searchEventLogger) {
        Intrinsics.checkNotNullParameter(searchEventLogger, "searchEventLogger");
        this.b = searchEventLogger;
        this.d = "";
        this.g = e0.c(null);
    }

    public abstract SearchType A();

    public abstract Y B(String str);

    public final InterfaceC4992i C(String query) {
        Intrinsics.checkNotNullParameter(query, "query");
        if (this.c == null || !Intrinsics.b(query, this.d)) {
            this.d = query;
            this.e = true;
            this.c = B(query);
        }
        InterfaceC4992i interfaceC4992i = this.c;
        if (interfaceC4992i != null) {
            return interfaceC4992i;
        }
        throw new IllegalStateException("Pager must be not null");
    }

    public final void D(com.quizlet.ui.models.impressions.a model, int i) {
        Intrinsics.checkNotNullParameter(model, "model");
        long itemId = model.getItemId();
        int modelType = model.getModelType();
        K0 k0A = model.a();
        SearchType searchTypeA = A();
        this.b.o(modelType, itemId, i + 1, searchTypeA, k0A);
    }

    public final void E(String sessionId, boolean z) {
        s0 s0Var;
        Object value;
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        this.f = z;
        if (sessionId.length() > 0) {
            this.b.r(A(), sessionId);
        }
        do {
            s0Var = this.g;
            value = s0Var.getValue();
        } while (!s0Var.k(value, new Pair(Boolean.TRUE, sessionId)));
    }
}
