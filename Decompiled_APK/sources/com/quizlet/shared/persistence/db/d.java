package com.quizlet.shared.persistence.db;

import app.cash.sqldelight.driver.android.j;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class d extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ e b;
    public final /* synthetic */ g c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(e eVar, g gVar, int i) {
        super(1);
        this.a = i;
        this.b = eVar;
        this.c = gVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                j execute = (j) obj;
                Intrinsics.checkNotNullParameter(execute, "$this$execute");
                e eVar = this.b;
                List list = eVar.c;
                com.quizlet.data.repository.login.a aVar = this.c.c;
                execute.g(0, list != null ? (String) ((com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c) aVar.c).d(list) : null);
                execute.b(1, Long.valueOf(eVar.d));
                execute.b(2, (Long) ((com.quizlet.quizletandroid.ui.joincontenttofolder.i) aVar.b).b(eVar.e));
                execute.b(3, (Long) ((com.quizlet.quizletandroid.ui.joincontenttofolder.i) aVar.a).b(eVar.f));
                break;
            case 1:
                j execute2 = (j) obj;
                Intrinsics.checkNotNullParameter(execute2, "$this$execute");
                e eVar2 = this.b;
                execute2.b(0, Long.valueOf(eVar2.d));
                com.quizlet.data.repository.login.a aVar2 = this.c.c;
                execute2.b(1, (Long) ((com.quizlet.quizletandroid.ui.joincontenttofolder.i) aVar2.b).b(eVar2.e));
                execute2.b(2, (Long) ((com.quizlet.quizletandroid.ui.joincontenttofolder.i) aVar2.a).b(eVar2.f));
                List list2 = eVar2.c;
                execute2.g(3, list2 != null ? (String) ((com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c) aVar2.c).d(list2) : null);
                break;
            default:
                j executeQuery = (j) obj;
                Intrinsics.checkNotNullParameter(executeQuery, "$this$executeQuery");
                e eVar3 = this.b;
                executeQuery.b(0, Long.valueOf(eVar3.d));
                com.quizlet.data.repository.login.a aVar3 = this.c.c;
                executeQuery.b(1, (Long) ((com.quizlet.quizletandroid.ui.joincontenttofolder.i) aVar3.b).b(eVar3.e));
                executeQuery.b(2, (Long) ((com.quizlet.quizletandroid.ui.joincontenttofolder.i) aVar3.a).b(eVar3.f));
                break;
        }
        return Unit.a;
    }
}
