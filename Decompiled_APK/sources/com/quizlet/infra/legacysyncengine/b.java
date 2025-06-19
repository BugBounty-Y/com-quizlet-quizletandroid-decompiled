package com.quizlet.infra.legacysyncengine;

import com.quizlet.db.data.models.base.Comparators;
import com.quizlet.infra.legacysyncengine.net.g;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements BiFunction {
    public final /* synthetic */ int a;

    @Override // java.util.function.BiFunction
    public final Object apply(Object obj, Object obj2) {
        g gVar = (g) obj2;
        switch (this.a) {
            case 0:
                if (gVar == null) {
                    gVar = new g(null, 0);
                }
                if (gVar.a == null) {
                    gVar.a = new ArrayList();
                    break;
                }
                break;
            case 1:
                if (gVar == null) {
                    gVar = new g(null, 0);
                }
                gVar.b.incrementAndGet();
                break;
            case 2:
                gVar.b.decrementAndGet();
                if (gVar.b.get() == 0) {
                }
                break;
            default:
                List list = gVar.a;
                if (list != null) {
                    list.sort(Comparators.DEFAULT_ASC);
                    break;
                }
                break;
        }
        return gVar;
    }
}
