package androidx.sqlite.db;

import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.util.Log;
import androidx.compose.animation.d0;
import java.io.File;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;

/* loaded from: classes.dex */
public abstract class b {
    public final /* synthetic */ int a;
    public int b;

    public static void a(String str) {
        if (D.l(str, ":memory:", true)) {
            return;
        }
        int length = str.length() - 1;
        int i = 0;
        boolean z = false;
        while (i <= length) {
            boolean z2 = Intrinsics.g(str.charAt(!z ? i : length), 32) <= 0;
            if (z) {
                if (!z2) {
                    break;
                } else {
                    length--;
                }
            } else if (z2) {
                i++;
            } else {
                z = true;
            }
        }
        if (str.subSequence(i, length + 1).toString().length() == 0) {
            return;
        }
        Log.w("SupportSQLite", "deleting the database file: ".concat(str));
        try {
            File file = new File(str);
            Intrinsics.checkNotNullParameter(file, "file");
            SQLiteDatabase.deleteDatabase(file);
        } catch (Exception e) {
            Log.w("SupportSQLite", "delete failed: ", e);
        }
    }

    public static void r(StringBuilder sb) {
        if (sb != null) {
            sb.delete(0, sb.length());
        }
    }

    public static String t(int i) {
        StringBuilder sb = new StringBuilder();
        sb.append((char) ((i >> 24) & 255));
        sb.append((char) ((i >> 16) & 255));
        sb.append((char) ((i >> 8) & 255));
        sb.append((char) (i & 255));
        return sb.toString();
    }

    public abstract int b();

    public abstract int c();

    public abstract int d();

    public abstract int e();

    public abstract int f();

    public boolean g() {
        return this.b == 4;
    }

    public boolean h() {
        return this.b == 1;
    }

    public boolean i() {
        return this.b == 6;
    }

    public boolean j() {
        return this.b == 3;
    }

    public boolean k() {
        return this.b == 2;
    }

    public void l(androidx.sqlite.db.framework.b db) {
        Intrinsics.checkNotNullParameter(db, "db");
    }

    public abstract void m(androidx.sqlite.db.framework.b bVar);

    public void n(androidx.sqlite.db.framework.b db, int i, int i2) {
        Intrinsics.checkNotNullParameter(db, "db");
        throw new SQLiteException(d0.p("Can't downgrade database from version ", i, " to ", i2));
    }

    public void o(androidx.sqlite.db.framework.b db) {
        Intrinsics.checkNotNullParameter(db, "db");
    }

    public abstract void p(androidx.sqlite.db.framework.b bVar, int i, int i2);

    public abstract void q();

    public boolean s(int i) {
        return (this.b & i) == i;
    }

    public String toString() {
        switch (this.a) {
            case 1:
                return t(this.b);
            default:
                return super.toString();
        }
    }

    public boolean u() {
        return s(1);
    }

    public /* synthetic */ b(int i, int i2) {
        this.a = i2;
        this.b = i;
    }
}
