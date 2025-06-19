package androidx.room;

import android.database.Cursor;
import android.database.SQLException;
import androidx.work.impl.C1429a;
import androidx.work.impl.WorkDatabase_Impl;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class t extends androidx.sqlite.db.b {
    public f c;
    public final com.airbnb.lottie.network.d d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(f configuration, com.airbnb.lottie.network.d delegate) {
        super(23, 0);
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        Intrinsics.checkNotNullParameter("86254750241babac4b8d52996a675549", "identityHash");
        Intrinsics.checkNotNullParameter("1cbd3130fa23b59692c061c594c16cc0", "legacyHash");
        this.c = configuration;
        this.d = delegate;
    }

    public static void v(androidx.sqlite.db.framework.b bVar) throws SQLException {
        bVar.j("CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)");
        Intrinsics.checkNotNullParameter("86254750241babac4b8d52996a675549", "hash");
        bVar.j("INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, '86254750241babac4b8d52996a675549')");
    }

    @Override // androidx.sqlite.db.b
    public final void l(androidx.sqlite.db.framework.b db) {
        Intrinsics.checkNotNullParameter(db, "db");
        super.l(db);
    }

    @Override // androidx.sqlite.db.b
    public final void m(androidx.sqlite.db.framework.b db) throws IOException, SQLException {
        Intrinsics.checkNotNullParameter(db, "db");
        Intrinsics.checkNotNullParameter(db, "db");
        Cursor cursorY = db.y("SELECT count(*) FROM sqlite_master WHERE name != 'android_metadata'");
        try {
            boolean z = false;
            if (cursorY.moveToFirst()) {
                if (cursorY.getInt(0) == 0) {
                    z = true;
                }
            }
            cursorY.close();
            com.airbnb.lottie.network.d dVar = this.d;
            com.airbnb.lottie.network.d.g(db);
            if (!z) {
                s sVarO = com.airbnb.lottie.network.d.o(db);
                if (!sVarO.c) {
                    throw new IllegalStateException("Pre-packaged database has an invalid schema: " + sVarO.b);
                }
            }
            v(db);
            ArrayList arrayList = ((WorkDatabase_Impl) dVar.b).g;
            if (arrayList != null) {
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    ((C1429a) it2.next()).getClass();
                    Intrinsics.checkNotNullParameter(db, "db");
                }
            }
        } catch (Throwable th) {
            try {
                throw th;
            } catch (Throwable th2) {
                AbstractC3336f.c(cursorY, th);
                throw th2;
            }
        }
    }

    @Override // androidx.sqlite.db.b
    public final void n(androidx.sqlite.db.framework.b db, int i, int i2) throws IOException, SQLException {
        Intrinsics.checkNotNullParameter(db, "db");
        p(db, i, i2);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0026  */
    @Override // androidx.sqlite.db.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void o(androidx.sqlite.db.framework.b r9) throws java.io.IOException, android.database.SQLException {
        /*
            Method dump skipped, instructions count: 320
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.room.t.o(androidx.sqlite.db.framework.b):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0031, code lost:
    
        r16 = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x009e, code lost:
    
        r7 = r11;
     */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0047 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x004a  */
    @Override // androidx.sqlite.db.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void p(androidx.sqlite.db.framework.b r18, int r19, int r20) throws java.io.IOException, android.database.SQLException {
        /*
            Method dump skipped, instructions count: 435
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.room.t.p(androidx.sqlite.db.framework.b, int, int):void");
    }
}
