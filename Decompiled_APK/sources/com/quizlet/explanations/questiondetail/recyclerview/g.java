package com.quizlet.explanations.questiondetail.recyclerview;

import com.braze.requests.framework.o;
import com.quizlet.data.model.SimpleImage;
import kotlin.jvm.functions.Function1;
import kotlin.u;

/* loaded from: classes2.dex */
public abstract class g implements com.quizlet.baserecyclerview.a {
    public final u a = kotlin.l.b(new o(this, 28));

    public abstract Function1 a();

    public abstract SimpleImage b();

    public abstract String c();

    public abstract boolean d();

    public abstract boolean e();

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return -1L;
    }
}
