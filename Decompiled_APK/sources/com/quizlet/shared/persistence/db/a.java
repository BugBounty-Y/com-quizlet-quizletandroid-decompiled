package com.quizlet.shared.persistence.db;

import android.database.Cursor;
import java.util.List;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class a extends r implements Function1 {
    public static final a b = new a(1, 0);
    public static final a c = new a(1, 1);
    public static final a d = new a(1, 2);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Integer numValueOf;
        switch (this.a) {
            case 0:
                app.cash.sqldelight.driver.android.a cursor = (app.cash.sqldelight.driver.android.a) obj;
                Intrinsics.checkNotNullParameter(cursor, "cursor");
                if (Boolean.valueOf(cursor.a.moveToNext()).booleanValue()) {
                    Cursor cursor2 = cursor.a;
                    Long lValueOf = cursor2.isNull(0) ? null : Long.valueOf(cursor2.getLong(0));
                    numValueOf = lValueOf != null ? Integer.valueOf((int) lValueOf.longValue()) : null;
                } else {
                    numValueOf = 0;
                }
                return new app.cash.sqldelight.db.c(Integer.valueOf(numValueOf != null ? numValueOf.intValue() : 0));
            case 1:
                return new h((List) obj);
            default:
                return new i((List) obj);
        }
    }
}
