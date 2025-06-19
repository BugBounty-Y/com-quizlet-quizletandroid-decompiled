package com.quizlet.shared.persistence.db;

import android.database.Cursor;
import java.util.List;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class f extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ g b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f(g gVar, int i) {
        super(1);
        this.a = i;
        this.b = gVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                app.cash.sqldelight.driver.android.a cursor = (app.cash.sqldelight.driver.android.a) obj;
                Intrinsics.checkNotNullParameter(cursor, "cursor");
                Cursor cursor2 = cursor.a;
                String string = cursor2.isNull(0) ? null : cursor2.getString(0);
                return new h(string != null ? (List) ((com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c) this.b.c.c).b(string) : null);
            default:
                app.cash.sqldelight.driver.android.a cursor3 = (app.cash.sqldelight.driver.android.a) obj;
                Intrinsics.checkNotNullParameter(cursor3, "cursor");
                Cursor cursor4 = cursor3.a;
                String string2 = cursor4.isNull(0) ? null : cursor4.getString(0);
                return new i(string2 != null ? (List) ((com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c) this.b.c.c).b(string2) : null);
        }
    }
}
