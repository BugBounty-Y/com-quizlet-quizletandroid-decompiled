package com.quizlet.quizletandroid.data.net.synchooks;

import android.content.Context;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.net.tasks.ExecutionRouter;

/* loaded from: classes3.dex */
public final class a {
    public final /* synthetic */ int a = 0;
    public final DatabaseHelper b;
    public final Object c;

    public a(Context context, DatabaseHelper databaseHelper) {
        this.c = context;
        this.b = databaseHelper;
    }

    public a(DatabaseHelper databaseHelper, ExecutionRouter executionRouter) {
        this.b = databaseHelper;
        this.c = executionRouter;
    }
}
