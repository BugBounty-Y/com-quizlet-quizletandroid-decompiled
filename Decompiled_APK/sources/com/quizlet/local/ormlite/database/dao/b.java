package com.quizlet.local.ormlite.database.dao;

import com.google.android.gms.internal.mlkit_vision_document_scanner.A;
import com.j256.ormlite.dao.Dao;
import com.quizlet.db.data.database.DatabaseHelper;
import io.reactivex.rxjava3.core.p;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.text.x;
import kotlin.u;

/* loaded from: classes3.dex */
public final class b implements com.quizlet.local.ormlite.database.b {
    public final /* synthetic */ int a;
    public final u b;

    public b(DatabaseHelper database, int i) {
        this.a = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(database, "database");
                this.b = l.b(new a(database, 9));
                break;
            default:
                Intrinsics.checkNotNullParameter(database, "database");
                this.b = l.b(new a(database, 0));
                break;
        }
    }

    public p a(List ids) {
        Intrinsics.checkNotNullParameter(ids, "ids");
        Object value = this.b.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        Intrinsics.checkNotNullParameter(ids, "ids");
        return com.quizlet.local.ormlite.util.b.b((Dao) value, x.c("\n                SELECT * FROM user\n                WHERE id IN " + A.b(ids) + "\n                AND isDeleted = 0\n        "));
    }

    @Override // com.quizlet.local.ormlite.database.b
    public final io.reactivex.rxjava3.internal.operators.completable.c f(List models) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(models, "models");
                Object value = this.b.getValue();
                Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
                return com.quizlet.local.ormlite.util.b.a((Dao) value, models);
            default:
                Intrinsics.checkNotNullParameter(models, "models");
                Object value2 = this.b.getValue();
                Intrinsics.checkNotNullExpressionValue(value2, "getValue(...)");
                return com.quizlet.local.ormlite.util.b.a((Dao) value2, models);
        }
    }
}
