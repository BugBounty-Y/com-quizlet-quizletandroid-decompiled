package com.quizlet.infra.legacysyncengine;

import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.infra.legacysyncengine.net.g;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements BiFunction {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.util.function.BiFunction
    public final Object apply(Object obj, Object obj2) {
        g gVar = (g) obj2;
        switch (this.a) {
            case 0:
                gVar.a.removeAll((ArrayList) this.b);
                return gVar;
            default:
                List list = gVar.a;
                if (list != null) {
                    DBModel dBModel = (DBModel) this.b;
                    if (dBModel.getIdentity().hasServerIdentity()) {
                        int iIndexOf = list.indexOf(dBModel);
                        if (iIndexOf >= 0) {
                            ((DBModel) list.get(iIndexOf)).setDirty(false);
                        }
                    } else {
                        list.remove(dBModel);
                    }
                }
                return new g(list, gVar.b.get());
        }
    }
}
