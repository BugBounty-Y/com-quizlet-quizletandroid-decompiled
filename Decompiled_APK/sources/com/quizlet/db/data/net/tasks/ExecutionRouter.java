package com.quizlet.db.data.net.tasks;

import android.os.Looper;
import com.google.firebase.crashlytics.internal.common.i;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.infra.legacysyncengine.tasks.parse.g;
import io.reactivex.rxjava3.core.o;
import java.sql.SQLException;
import java.util.concurrent.Callable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import timber.log.c;

@Metadata
/* loaded from: classes2.dex */
public final class ExecutionRouter {
    private static final int RX_COMPUTATION_PRIORITY = 3;

    @NotNull
    private static final String RX_COMPUTATION_PRIORITY_KEY = "rx3.computation-priority";
    private static final int RX_IO_PRIORITY = 4;

    @NotNull
    private static final String RX_IO_PRIORITY_KEY = "rx3.io-priority";
    private static final int RX_SINGLE_PRIORITY = 4;

    @NotNull
    private static final String RX_SINGLE_PRIORITY_KEY = "rx3.single-priority";

    @NotNull
    private final o computationScheduler;

    @NotNull
    private final DatabaseHelper database;

    @NotNull
    private final o databaseScheduler;

    @NotNull
    private final o mainThreadScheduler;

    @NotNull
    private final o networkScheduler;

    @Metadata
    public static final class Companion {
    }

    public ExecutionRouter(o networkScheduler, o databaseScheduler, o computationScheduler, o mainThreadScheduler, DatabaseHelper database) {
        Intrinsics.checkNotNullParameter(networkScheduler, "networkScheduler");
        Intrinsics.checkNotNullParameter(databaseScheduler, "databaseScheduler");
        Intrinsics.checkNotNullParameter(computationScheduler, "computationScheduler");
        Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
        Intrinsics.checkNotNullParameter(database, "database");
        this.networkScheduler = networkScheduler;
        this.databaseScheduler = databaseScheduler;
        this.computationScheduler = computationScheduler;
        this.mainThreadScheduler = mainThreadScheduler;
        this.database = database;
    }

    public static void a(ExecutionRouter executionRouter, Callable callable) {
        try {
            executionRouter.database.f(callable);
        } catch (SQLException e) {
            c.a.e(e);
        }
    }

    public final o b() {
        return this.computationScheduler;
    }

    public final o c() {
        return this.databaseScheduler;
    }

    public final void d(Runnable runnable) {
        Intrinsics.checkNotNullParameter(runnable, "runnable");
        this.computationScheduler.b(runnable);
    }

    public final void e(Runnable runnable) {
        Intrinsics.checkNotNullParameter(runnable, "runnable");
        this.databaseScheduler.b(runnable);
    }

    public final void f(Callable callable) {
        Intrinsics.checkNotNullParameter(callable, "callable");
        this.databaseScheduler.b(new i(17, this, callable));
    }

    public final void g(Runnable callback) {
        Intrinsics.checkNotNullParameter(callback, "callback");
        if (Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
            callback.run();
        } else {
            Intrinsics.d(this.mainThreadScheduler.b(callback));
        }
    }

    public final void h(g runnable) {
        Intrinsics.checkNotNullParameter(runnable, "runnable");
        this.networkScheduler.b(runnable);
    }

    public final o i() {
        return this.mainThreadScheduler;
    }
}
