package com.quizlet.db.data.net.localid;

import androidx.collection.C0219q;
import com.quizlet.db.data.models.persisted.base.ModelType;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.subjects.p;
import java.util.HashMap;

/* loaded from: classes2.dex */
public class LocalIdMap {
    public final HashMap b = new HashMap();
    public final p a = p.z();

    public final Long a(ModelType modelType, Long l) {
        C0219q c0219q = (C0219q) this.b.get(modelType);
        if (c0219q != null) {
            return (Long) c0219q.c(l.longValue());
        }
        return null;
    }

    public i getServerIdAssignmentObservable() {
        return this.a;
    }
}
