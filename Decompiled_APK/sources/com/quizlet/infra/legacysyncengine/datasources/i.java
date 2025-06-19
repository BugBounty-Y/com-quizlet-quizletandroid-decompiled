package com.quizlet.infra.legacysyncengine.datasources;

import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class i implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ n b;

    public /* synthetic */ i(n nVar, int i) {
        this.a = i;
        this.b = nVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        List list = (List) obj;
        switch (this.a) {
            case 0:
                if (list != null) {
                    this.b.d.b(list);
                }
                break;
            default:
                if (list != null) {
                    this.b.e.b(list);
                }
                break;
        }
        return Unit.a;
    }
}
