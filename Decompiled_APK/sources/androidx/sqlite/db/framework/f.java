package androidx.sqlite.db.framework;

import android.content.Context;
import android.database.DatabaseErrorHandler;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;
import android.util.Pair;
import androidx.compose.ui.node.B;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3355j2;
import java.io.File;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f extends SQLiteOpenHelper implements AutoCloseable {
    public static final /* synthetic */ int h = 0;
    public final Context a;
    public final com.airbnb.lottie.network.c b;
    public final androidx.sqlite.db.b c;
    public final boolean d;
    public boolean e;
    public final androidx.sqlite.util.a f;
    public boolean g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(Context context, String str, final com.airbnb.lottie.network.c dbRef, final androidx.sqlite.db.b callback, boolean z) {
        super(context, str, null, callback.b, new DatabaseErrorHandler() { // from class: androidx.sqlite.db.framework.c
            @Override // android.database.DatabaseErrorHandler
            public final void onCorruption(SQLiteDatabase dbObj) {
                androidx.sqlite.db.b callback2 = callback;
                Intrinsics.checkNotNullParameter(callback2, "$callback");
                com.airbnb.lottie.network.c dbRef2 = dbRef;
                Intrinsics.checkNotNullParameter(dbRef2, "$dbRef");
                int i = f.h;
                Intrinsics.checkNotNullExpressionValue(dbObj, "dbObj");
                b db = AbstractC3355j2.c(dbRef2, dbObj);
                callback2.getClass();
                Intrinsics.checkNotNullParameter(db, "db");
                Log.e("SupportSQLite", "Corruption reported by sqlite on database: " + db + ".path");
                SQLiteDatabase sQLiteDatabase = db.a;
                if (!sQLiteDatabase.isOpen()) {
                    String path = sQLiteDatabase.getPath();
                    if (path != null) {
                        androidx.sqlite.db.b.a(path);
                        return;
                    }
                    return;
                }
                List<Pair<String, String>> attachedDbs = null;
                try {
                    try {
                        attachedDbs = sQLiteDatabase.getAttachedDbs();
                    } finally {
                        if (attachedDbs != null) {
                            Iterator<T> it2 = attachedDbs.iterator();
                            while (it2.hasNext()) {
                                Object obj = ((Pair) it2.next()).second;
                                Intrinsics.checkNotNullExpressionValue(obj, "p.second");
                                androidx.sqlite.db.b.a((String) obj);
                            }
                        } else {
                            String path2 = sQLiteDatabase.getPath();
                            if (path2 != null) {
                                androidx.sqlite.db.b.a(path2);
                            }
                        }
                    }
                } catch (SQLiteException unused) {
                }
                try {
                    db.close();
                } catch (IOException unused2) {
                }
                if (attachedDbs != null) {
                    return;
                }
            }
        });
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(dbRef, "dbRef");
        Intrinsics.checkNotNullParameter(callback, "callback");
        this.a = context;
        this.b = dbRef;
        this.c = callback;
        this.d = z;
        this.f = new androidx.sqlite.util.a(str == null ? B.f("randomUUID().toString()") : str, context.getCacheDir(), false);
    }

    public final b a(boolean z) throws IOException {
        androidx.sqlite.util.a aVar = this.f;
        try {
            aVar.a((this.g || getDatabaseName() == null) ? false : true);
            this.e = false;
            SQLiteDatabase sQLiteDatabaseI = i(z);
            if (!this.e) {
                b bVarD = d(sQLiteDatabaseI);
                aVar.b();
                return bVarD;
            }
            close();
            b bVarA = a(z);
            aVar.b();
            return bVarA;
        } catch (Throwable th) {
            aVar.b();
            throw th;
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper, java.lang.AutoCloseable
    public final void close() throws IOException {
        androidx.sqlite.util.a aVar = this.f;
        try {
            aVar.a(aVar.a);
            super.close();
            this.b.b = null;
            this.g = false;
        } finally {
            aVar.b();
        }
    }

    public final b d(SQLiteDatabase sqLiteDatabase) {
        Intrinsics.checkNotNullParameter(sqLiteDatabase, "sqLiteDatabase");
        return AbstractC3355j2.c(this.b, sqLiteDatabase);
    }

    public final SQLiteDatabase f(boolean z) {
        if (z) {
            SQLiteDatabase writableDatabase = getWritableDatabase();
            Intrinsics.checkNotNullExpressionValue(writableDatabase, "{\n                super.…eDatabase()\n            }");
            return writableDatabase;
        }
        SQLiteDatabase readableDatabase = getReadableDatabase();
        Intrinsics.checkNotNullExpressionValue(readableDatabase, "{\n                super.…eDatabase()\n            }");
        return readableDatabase;
    }

    public final SQLiteDatabase i(boolean z) throws Throwable {
        File parentFile;
        String databaseName = getDatabaseName();
        boolean z2 = this.g;
        Context context = this.a;
        if (databaseName != null && !z2 && (parentFile = context.getDatabasePath(databaseName).getParentFile()) != null) {
            parentFile.mkdirs();
            if (!parentFile.isDirectory()) {
                Log.w("SupportSQLite", "Invalid database parent file, not a directory: " + parentFile);
            }
        }
        try {
            return f(z);
        } catch (Throwable unused) {
            super.close();
            try {
                Thread.sleep(500L);
            } catch (InterruptedException unused2) {
            }
            try {
                return f(z);
            } catch (Throwable th) {
                super.close();
                if (th instanceof d) {
                    d dVar = th;
                    int iOrdinal = dVar.a.ordinal();
                    Throwable th2 = dVar.b;
                    if (iOrdinal == 0 || iOrdinal == 1 || iOrdinal == 2 || iOrdinal == 3 || !(th2 instanceof SQLiteException)) {
                        throw th2;
                    }
                } else if (!(th instanceof SQLiteException) || databaseName == null || !this.d) {
                    throw th;
                }
                context.deleteDatabase(databaseName);
                try {
                    return f(z);
                } catch (d e) {
                    throw e.b;
                }
            }
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onConfigure(SQLiteDatabase db) {
        Intrinsics.checkNotNullParameter(db, "db");
        boolean z = this.e;
        androidx.sqlite.db.b bVar = this.c;
        if (!z && bVar.b != db.getVersion()) {
            db.setMaxSqlCacheSize(1);
        }
        try {
            bVar.l(d(db));
        } catch (Throwable th) {
            throw new d(e.a, th);
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onCreate(SQLiteDatabase sqLiteDatabase) {
        Intrinsics.checkNotNullParameter(sqLiteDatabase, "sqLiteDatabase");
        try {
            this.c.m(d(sqLiteDatabase));
        } catch (Throwable th) {
            throw new d(e.b, th);
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onDowngrade(SQLiteDatabase db, int i, int i2) {
        Intrinsics.checkNotNullParameter(db, "db");
        this.e = true;
        try {
            this.c.n(d(db), i, i2);
        } catch (Throwable th) {
            throw new d(e.d, th);
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onOpen(SQLiteDatabase db) {
        Intrinsics.checkNotNullParameter(db, "db");
        if (!this.e) {
            try {
                this.c.o(d(db));
            } catch (Throwable th) {
                throw new d(e.e, th);
            }
        }
        this.g = true;
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onUpgrade(SQLiteDatabase sqLiteDatabase, int i, int i2) {
        Intrinsics.checkNotNullParameter(sqLiteDatabase, "sqLiteDatabase");
        this.e = true;
        try {
            this.c.p(d(sqLiteDatabase), i, i2);
        } catch (Throwable th) {
            throw new d(e.c, th);
        }
    }
}
