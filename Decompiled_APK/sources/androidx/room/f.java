package androidx.room;

import android.content.Context;
import androidx.appcompat.app.Q;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f {
    public final Context a;
    public final String b;
    public final androidx.sqlite.db.d c;
    public final Q d;
    public final ArrayList e;
    public final boolean f;
    public final r g;
    public final Executor h;
    public final Executor i;
    public final boolean j;
    public final boolean k;
    public final LinkedHashSet l;
    public final ArrayList m;
    public final ArrayList n;

    public f(Context context, String str, androidx.sqlite.db.d sqliteOpenHelperFactory, Q migrationContainer, ArrayList arrayList, boolean z, r journalMode, Executor queryExecutor, Executor transactionExecutor, boolean z2, boolean z3, LinkedHashSet linkedHashSet, ArrayList typeConverters, ArrayList autoMigrationSpecs) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(sqliteOpenHelperFactory, "sqliteOpenHelperFactory");
        Intrinsics.checkNotNullParameter(migrationContainer, "migrationContainer");
        Intrinsics.checkNotNullParameter(journalMode, "journalMode");
        Intrinsics.checkNotNullParameter(queryExecutor, "queryExecutor");
        Intrinsics.checkNotNullParameter(transactionExecutor, "transactionExecutor");
        Intrinsics.checkNotNullParameter(typeConverters, "typeConverters");
        Intrinsics.checkNotNullParameter(autoMigrationSpecs, "autoMigrationSpecs");
        this.a = context;
        this.b = str;
        this.c = sqliteOpenHelperFactory;
        this.d = migrationContainer;
        this.e = arrayList;
        this.f = z;
        this.g = journalMode;
        this.h = queryExecutor;
        this.i = transactionExecutor;
        this.j = z2;
        this.k = z3;
        this.l = linkedHashSet;
        this.m = typeConverters;
        this.n = autoMigrationSpecs;
    }
}
