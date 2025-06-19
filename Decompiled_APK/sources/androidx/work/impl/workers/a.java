package androidx.work.impl.workers;

import android.database.Cursor;
import androidx.room.u;
import androidx.work.impl.WorkDatabase_Impl;
import androidx.work.impl.model.g;
import androidx.work.impl.model.i;
import androidx.work.impl.model.l;
import androidx.work.impl.model.q;
import androidx.work.impl.model.v;
import androidx.work.z;
import com.google.android.gms.internal.mlkit_vision_camera.A2;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class a {
    public static final String a;

    static {
        String strE = z.e("DiagnosticsWrkr");
        Intrinsics.checkNotNullExpressionValue(strE, "tagWithPrefix(\"DiagnosticsWrkr\")");
        a = strE;
    }

    public static final String a(l lVar, v vVar, i iVar, ArrayList arrayList) {
        StringBuilder sb = new StringBuilder("\n Id \t Class Name\t Job Id\t State\t Unique Name\t Tags\t");
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            q qVar = (q) it2.next();
            g gVarD = iVar.d(A2.a(qVar));
            Integer numValueOf = gVarD != null ? Integer.valueOf(gVarD.c) : null;
            lVar.getClass();
            u uVarA = u.a(1, "SELECT name FROM workname WHERE work_spec_id=?");
            String str = qVar.a;
            uVarA.g(1, str);
            WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) lVar.b;
            workDatabase_Impl.b();
            Cursor cursorN = W1.N(workDatabase_Impl, uVarA, false);
            try {
                ArrayList arrayList2 = new ArrayList(cursorN.getCount());
                while (cursorN.moveToNext()) {
                    arrayList2.add(cursorN.getString(0));
                }
                cursorN.close();
                uVarA.i();
                String strS = CollectionsKt.S(arrayList2, ",", null, null, null, 62);
                String strS2 = CollectionsKt.S(vVar.g(str), ",", null, null, null, 62);
                StringBuilder sbY = android.support.v4.media.session.a.y("\n", str, "\t ");
                sbY.append(qVar.c);
                sbY.append("\t ");
                sbY.append(numValueOf);
                sbY.append("\t ");
                sbY.append(qVar.b.name());
                sbY.append("\t ");
                sbY.append(strS);
                sbY.append("\t ");
                sbY.append(strS2);
                sbY.append('\t');
                sb.append(sbY.toString());
            } catch (Throwable th) {
                cursorN.close();
                uVarA.i();
                throw th;
            }
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "StringBuilder().apply(builderAction).toString()");
        return string;
    }
}
