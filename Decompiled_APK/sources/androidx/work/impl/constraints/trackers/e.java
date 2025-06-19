package androidx.work.impl.constraints.trackers;

import android.content.Context;
import com.google.android.datatransport.cct.internal.s;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import java.io.PipedOutputStream;
import java.util.LinkedHashSet;
import java.util.UUID;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class e {
    public final Object a;
    public final Object b;
    public final Object c;
    public Object d;
    public final Object e;

    public e(Context context, androidx.work.impl.utils.taskexecutor.c taskExecutor) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(taskExecutor, "taskExecutor");
        this.a = taskExecutor;
        Context applicationContext = context.getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(applicationContext, "context.applicationContext");
        this.b = applicationContext;
        this.c = new Object();
        this.e = new LinkedHashSet();
    }

    public abstract com.quizlet.infra.legacysyncengine.tasks.parse.g a(PipedOutputStream pipedOutputStream);

    public abstract com.quizlet.infra.legacysyncengine.net.constants.a b();

    public abstract Object c();

    public void d(Object obj) {
        synchronized (this.c) {
            Object obj2 = this.d;
            if (obj2 == null || !obj2.equals(obj)) {
                this.d = obj;
                ((androidx.work.impl.utils.taskexecutor.c) this.a).d.execute(new androidx.credentials.playservices.controllers.c(8, CollectionsKt.w0((LinkedHashSet) this.e), this));
                Unit unit = Unit.a;
            }
        }
    }

    public abstract void e();

    public abstract void f();

    public e(ExecutionRouter executionRouter, androidx.work.impl.model.c cVar, com.quizlet.infra.legacysyncengine.tasks.parse.f fVar, s sVar, com.squareup.otto.c cVar2) {
        this.a = executionRouter;
        this.c = cVar;
        this.b = fVar;
        this.d = sVar;
        this.e = cVar2;
        UUID.randomUUID();
    }
}
