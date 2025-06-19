package androidx.room;

import android.content.Context;
import androidx.appcompat.app.Q;
import androidx.work.impl.WorkDatabase;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class q {
    public final Context a;
    public final String b;
    public final ArrayList c;
    public final ArrayList d;
    public final ArrayList e;
    public Executor f;
    public Executor g;
    public androidx.work.impl.o h;
    public boolean i;
    public final r j;
    public boolean k;
    public boolean l;
    public final long m;
    public final Q n;
    public final LinkedHashSet o;
    public HashSet p;

    public q(Context context, String str) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(WorkDatabase.class, "klass");
        this.a = context;
        this.b = str;
        this.c = new ArrayList();
        this.d = new ArrayList();
        this.e = new ArrayList();
        this.j = r.a;
        this.k = true;
        this.m = -1L;
        this.n = new Q(13);
        this.o = new LinkedHashSet();
    }

    public final void a(androidx.room.migration.a... migrations) {
        Intrinsics.checkNotNullParameter(migrations, "migrations");
        if (this.p == null) {
            this.p = new HashSet();
        }
        for (androidx.room.migration.a aVar : migrations) {
            HashSet hashSet = this.p;
            Intrinsics.d(hashSet);
            hashSet.add(Integer.valueOf(aVar.a));
            HashSet hashSet2 = this.p;
            Intrinsics.d(hashSet2);
            hashSet2.add(Integer.valueOf(aVar.b));
        }
        this.n.z((androidx.room.migration.a[]) Arrays.copyOf(migrations, migrations.length));
    }
}
