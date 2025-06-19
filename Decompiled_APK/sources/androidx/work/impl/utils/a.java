package androidx.work.impl.utils;

import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.work.impl.WorkDatabase;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.work.impl.r b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(androidx.work.impl.r rVar, int i) {
        super(0);
        this.a = i;
        this.b = rVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                androidx.work.impl.r workManagerImpl = this.b;
                Intrinsics.checkNotNullParameter("WidgetUpdate", "name");
                Intrinsics.checkNotNullParameter(workManagerImpl, "workManagerImpl");
                WorkDatabase workDatabase = workManagerImpl.c;
                Intrinsics.checkNotNullExpressionValue(workDatabase, "workManagerImpl.workDatabase");
                workDatabase.o(new RunnableC0130g(workDatabase, "WidgetUpdate", workManagerImpl, 18));
                androidx.work.impl.i.b(workManagerImpl.b, workManagerImpl.c, workManagerImpl.e);
                break;
            default:
                androidx.work.impl.r rVar = this.b;
                WorkDatabase workDatabase2 = rVar.c;
                Intrinsics.checkNotNullExpressionValue(workDatabase2, "workManagerImpl.workDatabase");
                workDatabase2.o(new androidx.credentials.playservices.controllers.c(10, workDatabase2, rVar));
                androidx.work.impl.i.b(rVar.b, rVar.c, rVar.e);
                break;
        }
        return Unit.a;
    }
}
