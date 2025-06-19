package androidx.work.impl.model;

import android.database.Cursor;
import androidx.work.C1425f;
import androidx.work.C1437k;
import androidx.work.N;
import androidx.work.impl.WorkDatabase_Impl;
import com.google.android.gms.internal.mlkit_vision_camera.B2;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.Callable;

/* loaded from: classes.dex */
public final class s implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.room.u b;
    public final /* synthetic */ t c;

    public /* synthetic */ s(t tVar, androidx.room.u uVar, int i) {
        this.a = i;
        this.c = tVar;
        this.b = uVar;
    }

    /* JADX WARN: Finally extract failed */
    @Override // java.util.concurrent.Callable
    public final Object call() {
        Cursor cursorN;
        Boolean boolValueOf;
        switch (this.a) {
            case 0:
                t tVar = this.c;
                WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) tVar.a;
                workDatabase_Impl.c();
                try {
                    cursorN = W1.N(workDatabase_Impl, this.b, true);
                    try {
                        HashMap map = new HashMap();
                        HashMap map2 = new HashMap();
                        while (cursorN.moveToNext()) {
                            String string = cursorN.getString(0);
                            if (!map.containsKey(string)) {
                                map.put(string, new ArrayList());
                            }
                            String string2 = cursorN.getString(0);
                            if (!map2.containsKey(string2)) {
                                map2.put(string2, new ArrayList());
                            }
                        }
                        cursorN.moveToPosition(-1);
                        tVar.b(map);
                        tVar.a(map2);
                        ArrayList arrayList = new ArrayList(cursorN.getCount());
                        while (cursorN.moveToNext()) {
                            String string3 = cursorN.getString(0);
                            N nF = B2.f(cursorN.getInt(1));
                            C1437k c1437kA = C1437k.a(cursorN.getBlob(2));
                            int i = cursorN.getInt(3);
                            int i2 = cursorN.getInt(4);
                            arrayList.add(new p(string3, nF, c1437kA, cursorN.getLong(14), cursorN.getLong(15), cursorN.getLong(16), new C1425f(B2.h(cursorN.getBlob(6)), B2.d(cursorN.getInt(5)), cursorN.getInt(7) != 0, cursorN.getInt(8) != 0, cursorN.getInt(9) != 0, cursorN.getInt(10) != 0, cursorN.getLong(11), cursorN.getLong(12), B2.a(cursorN.getBlob(13))), i, B2.c(cursorN.getInt(17)), cursorN.getLong(18), cursorN.getLong(19), cursorN.getInt(20), i2, cursorN.getLong(21), cursorN.getInt(22), (ArrayList) map.get(cursorN.getString(0)), (ArrayList) map2.get(cursorN.getString(0))));
                        }
                        workDatabase_Impl.p();
                        cursorN.close();
                        return arrayList;
                    } finally {
                        cursorN.close();
                    }
                } finally {
                    workDatabase_Impl.k();
                }
            default:
                cursorN = W1.N((WorkDatabase_Impl) this.c.a, this.b, false);
                try {
                    if (cursorN.moveToFirst()) {
                        boolValueOf = Boolean.valueOf(cursorN.getInt(0) != 0);
                    } else {
                        boolValueOf = Boolean.FALSE;
                    }
                    return boolValueOf;
                } catch (Throwable th) {
                    cursorN.close();
                    throw th;
                }
        }
    }

    public final void finalize() {
        switch (this.a) {
            case 0:
                this.b.i();
                break;
            default:
                this.b.i();
                break;
        }
    }
}
