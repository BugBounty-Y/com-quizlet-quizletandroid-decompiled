package com.quizlet.features.match.game;

import com.quizlet.db.data.models.persisted.DBImageRef;
import com.quizlet.db.data.models.persisted.DBStudySet;
import io.reactivex.rxjava3.functions.d;
import io.reactivex.rxjava3.subjects.r;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements d {
    public final /* synthetic */ int a;
    public final /* synthetic */ r b;

    public /* synthetic */ b(r rVar, int i) {
        this.a = i;
        this.b = rVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                Long p0 = (Long) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                this.b.onSuccess(p0);
                break;
            case 1:
                DBStudySet p02 = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                this.b.onSuccess(p02);
                break;
            case 2:
                DBImageRef p03 = (DBImageRef) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                this.b.onSuccess(p03);
                break;
            case 3:
                List p04 = (List) obj;
                Intrinsics.checkNotNullParameter(p04, "p0");
                this.b.onSuccess(p04);
                break;
            default:
                Long p05 = (Long) obj;
                Intrinsics.checkNotNullParameter(p05, "p0");
                this.b.onSuccess(p05);
                break;
        }
    }
}
