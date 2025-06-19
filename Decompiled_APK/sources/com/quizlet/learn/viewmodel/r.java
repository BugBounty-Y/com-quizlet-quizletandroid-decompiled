package com.quizlet.learn.viewmodel;

import assistantMode.types.aliases.ExperimentConfiguration;
import com.quizlet.data.model.C4127f1;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.generated.enums.A1;
import com.quizlet.learn.data.C4537b;
import java.util.List;
import java.util.Map;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.c {
    public G j;
    public C4537b k;
    public List l;
    public List m;
    public QuestionSettings n;
    public A1 o;
    public C4127f1 p;
    public Map q;
    public Map r;
    public ExperimentConfiguration s;
    public boolean t;
    public /* synthetic */ Object u;
    public final /* synthetic */ G v;
    public int w;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(G g, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.v = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.u = obj;
        this.w |= Integer.MIN_VALUE;
        List list = G.D1;
        return this.v.J(null, null, null, null, null, false, this);
    }
}
