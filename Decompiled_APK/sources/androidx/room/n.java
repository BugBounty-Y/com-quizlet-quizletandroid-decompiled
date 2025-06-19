package androidx.room;

import android.database.SQLException;
import android.database.sqlite.SQLiteException;
import android.util.Log;
import androidx.appcompat.app.J;
import androidx.compose.ui.node.B;
import androidx.work.impl.WorkDatabase_Impl;
import com.google.android.gms.internal.mlkit_vision_camera.U1;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class n {
    public static final String[] o = {"UPDATE", "DELETE", "INSERT"};
    public final WorkDatabase_Impl a;
    public final HashMap b;
    public final HashMap c;
    public final LinkedHashMap d;
    public final String[] e;
    public final AtomicBoolean f;
    public volatile boolean g;
    public volatile androidx.sqlite.db.framework.i h;
    public final androidx.browser.customtabs.k i;
    public final com.quizlet.data.repository.searchexplanations.c j;
    public final androidx.arch.core.internal.f k;
    public final Object l;
    public final Object m;
    public final J n;

    public n(WorkDatabase_Impl database, HashMap shadowTablesMap, HashMap viewTables, String... tableNames) {
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(shadowTablesMap, "shadowTablesMap");
        Intrinsics.checkNotNullParameter(viewTables, "viewTables");
        Intrinsics.checkNotNullParameter(tableNames, "tableNames");
        this.a = database;
        this.b = shadowTablesMap;
        this.c = viewTables;
        this.f = new AtomicBoolean(false);
        this.i = new androidx.browser.customtabs.k(tableNames.length);
        this.j = new com.quizlet.data.repository.searchexplanations.c(database);
        this.k = new androidx.arch.core.internal.f();
        this.l = new Object();
        this.m = new Object();
        this.d = new LinkedHashMap();
        int length = tableNames.length;
        String[] strArr = new String[length];
        for (int i = 0; i < length; i++) {
            String str = tableNames[i];
            Locale locale = Locale.US;
            String strK = B.k(locale, "US", str, locale, "this as java.lang.String).toLowerCase(locale)");
            this.d.put(strK, Integer.valueOf(i));
            String str2 = (String) this.b.get(tableNames[i]);
            String strK2 = str2 != null ? B.k(locale, "US", str2, locale, "this as java.lang.String).toLowerCase(locale)") : null;
            if (strK2 != null) {
                strK = strK2;
            }
            strArr[i] = strK;
        }
        this.e = strArr;
        for (Map.Entry entry : this.b.entrySet()) {
            String str3 = (String) entry.getValue();
            Locale locale2 = Locale.US;
            String strK3 = B.k(locale2, "US", str3, locale2, "this as java.lang.String).toLowerCase(locale)");
            if (this.d.containsKey(strK3)) {
                String strK4 = B.k(locale2, "US", (String) entry.getKey(), locale2, "this as java.lang.String).toLowerCase(locale)");
                LinkedHashMap linkedHashMap = this.d;
                linkedHashMap.put(strK4, V.d(strK3, linkedHashMap));
            }
        }
        this.n = new J(this, 12);
    }

    public final void a(k observer) {
        Object obj;
        l lVar;
        boolean z;
        WorkDatabase_Impl workDatabase_Impl;
        androidx.sqlite.db.framework.b bVar;
        Intrinsics.checkNotNullParameter(observer, "observer");
        String[] strArrD = d(observer.a);
        ArrayList arrayList = new ArrayList(strArrD.length);
        for (String str : strArrD) {
            LinkedHashMap linkedHashMap = this.d;
            Locale locale = Locale.US;
            Integer num = (Integer) linkedHashMap.get(B.k(locale, "US", str, locale, "this as java.lang.String).toLowerCase(locale)"));
            if (num == null) {
                throw new IllegalArgumentException("There is no table with name ".concat(str));
            }
            arrayList.add(num);
        }
        int[] iArrV0 = CollectionsKt.v0(arrayList);
        l lVar2 = new l(observer, iArrV0, strArrD);
        synchronized (this.k) {
            androidx.arch.core.internal.f fVar = this.k;
            androidx.arch.core.internal.c cVarA = fVar.a(observer);
            if (cVarA != null) {
                obj = cVarA.b;
            } else {
                androidx.arch.core.internal.c cVar = new androidx.arch.core.internal.c(observer, lVar2);
                fVar.d++;
                androidx.arch.core.internal.c cVar2 = fVar.b;
                if (cVar2 == null) {
                    fVar.a = cVar;
                    fVar.b = cVar;
                } else {
                    cVar2.c = cVar;
                    cVar.d = cVar2;
                    fVar.b = cVar;
                }
                obj = null;
            }
            lVar = (l) obj;
        }
        if (lVar == null) {
            androidx.browser.customtabs.k kVar = this.i;
            int[] tableIds = Arrays.copyOf(iArrV0, iArrV0.length);
            kVar.getClass();
            Intrinsics.checkNotNullParameter(tableIds, "tableIds");
            synchronized (kVar) {
                try {
                    z = false;
                    for (int i : tableIds) {
                        long[] jArr = (long[]) kVar.b;
                        long j = jArr[i];
                        jArr[i] = 1 + j;
                        if (j == 0) {
                            kVar.a = true;
                            z = true;
                        }
                    }
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
            }
            if (z && (bVar = (workDatabase_Impl = this.a).a) != null && bVar.a.isOpen()) {
                f(workDatabase_Impl.h().I());
            }
        }
    }

    public final boolean b() {
        androidx.sqlite.db.framework.b bVar = this.a.a;
        if (!(bVar != null && bVar.a.isOpen())) {
            return false;
        }
        if (!this.g) {
            this.a.h().I();
        }
        if (this.g) {
            return true;
        }
        Log.e("ROOM", "database is not initialized even though it is open");
        return false;
    }

    public final void c(k observer) {
        l lVar;
        boolean z;
        WorkDatabase_Impl workDatabase_Impl;
        androidx.sqlite.db.framework.b bVar;
        Intrinsics.checkNotNullParameter(observer, "observer");
        synchronized (this.k) {
            lVar = (l) this.k.b(observer);
        }
        if (lVar != null) {
            androidx.browser.customtabs.k kVar = this.i;
            int[] iArr = lVar.b;
            int[] tableIds = Arrays.copyOf(iArr, iArr.length);
            kVar.getClass();
            Intrinsics.checkNotNullParameter(tableIds, "tableIds");
            synchronized (kVar) {
                try {
                    z = false;
                    for (int i : tableIds) {
                        long[] jArr = (long[]) kVar.b;
                        long j = jArr[i];
                        jArr[i] = j - 1;
                        if (j == 1) {
                            kVar.a = true;
                            z = true;
                        }
                    }
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
            }
            if (z && (bVar = (workDatabase_Impl = this.a).a) != null && bVar.a.isOpen()) {
                f(workDatabase_Impl.h().I());
            }
        }
    }

    public final String[] d(String[] strArr) {
        kotlin.collections.builders.p pVar = new kotlin.collections.builders.p();
        for (String str : strArr) {
            Locale locale = Locale.US;
            String strK = B.k(locale, "US", str, locale, "this as java.lang.String).toLowerCase(locale)");
            HashMap map = this.c;
            if (map.containsKey(strK)) {
                Object obj = map.get(B.k(locale, "US", str, locale, "this as java.lang.String).toLowerCase(locale)"));
                Intrinsics.d(obj);
                pVar.addAll((Collection) obj);
            } else {
                pVar.add(str);
            }
        }
        return (String[]) Z.a(pVar).toArray(new String[0]);
    }

    public final void e(androidx.sqlite.db.framework.b bVar, int i) throws SQLException {
        bVar.j("INSERT OR IGNORE INTO room_table_modification_log VALUES(" + i + ", 0)");
        String str = this.e[i];
        String[] strArr = o;
        for (int i2 = 0; i2 < 3; i2++) {
            String str2 = strArr[i2];
            String str3 = "CREATE TEMP TRIGGER IF NOT EXISTS " + U1.c(str, str2) + " AFTER " + str2 + " ON `" + str + "` BEGIN UPDATE room_table_modification_log SET invalidated = 1 WHERE table_id = " + i + " AND invalidated = 0; END";
            Intrinsics.checkNotNullExpressionValue(str3, "StringBuilder().apply(builderAction).toString()");
            bVar.j(str3);
        }
    }

    public final void f(androidx.sqlite.db.framework.b database) {
        Intrinsics.checkNotNullParameter(database, "database");
        if (database.p()) {
            return;
        }
        try {
            ReentrantReadWriteLock.ReadLock lock = this.a.i.readLock();
            Intrinsics.checkNotNullExpressionValue(lock, "readWriteLock.readLock()");
            lock.lock();
            try {
                synchronized (this.l) {
                    int[] iArrH = this.i.h();
                    if (iArrH != null) {
                        Intrinsics.checkNotNullParameter(database, "database");
                        if (database.q()) {
                            database.d();
                        } else {
                            database.a();
                        }
                        try {
                            int length = iArrH.length;
                            int i = 0;
                            int i2 = 0;
                            while (i < length) {
                                int i3 = iArrH[i];
                                int i4 = i2 + 1;
                                if (i3 == 1) {
                                    e(database, i2);
                                } else if (i3 == 2) {
                                    String str = this.e[i2];
                                    String[] strArr = o;
                                    for (int i5 = 0; i5 < 3; i5++) {
                                        String str2 = "DROP TRIGGER IF EXISTS " + U1.c(str, strArr[i5]);
                                        Intrinsics.checkNotNullExpressionValue(str2, "StringBuilder().apply(builderAction).toString()");
                                        database.j(str2);
                                    }
                                }
                                i++;
                                i2 = i4;
                            }
                            database.B();
                            database.i();
                            Unit unit = Unit.a;
                        } catch (Throwable th) {
                            database.i();
                            throw th;
                        }
                    }
                }
            } finally {
                lock.unlock();
            }
        } catch (SQLiteException e) {
            Log.e("ROOM", "Cannot run invalidation tracker. Is the db closed?", e);
        } catch (IllegalStateException e2) {
            Log.e("ROOM", "Cannot run invalidation tracker. Is the db closed?", e2);
        }
    }
}
