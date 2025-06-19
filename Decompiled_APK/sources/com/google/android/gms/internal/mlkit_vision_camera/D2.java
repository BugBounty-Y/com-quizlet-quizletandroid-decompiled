package com.google.android.gms.internal.mlkit_vision_camera;

import android.database.Cursor;
import androidx.work.C1422c;
import androidx.work.impl.WorkDatabase;
import androidx.work.impl.WorkDatabase_Impl;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.xml.sax.Attributes;

/* loaded from: classes2.dex */
public abstract class D2 {
    public static final /* synthetic */ int a = 0;

    public static final void a(WorkDatabase workDatabase, C1422c configuration, androidx.work.impl.n continuation) {
        int i;
        Intrinsics.checkNotNullParameter(workDatabase, "workDatabase");
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        Intrinsics.checkNotNullParameter(continuation, "continuation");
        ArrayList arrayListK = kotlin.collections.B.k(continuation);
        int i2 = 0;
        while (!arrayListK.isEmpty()) {
            List list = ((androidx.work.impl.n) kotlin.collections.G.A(arrayListK)).d;
            Intrinsics.checkNotNullExpressionValue(list, "current.work");
            if (list == null || !list.isEmpty()) {
                Iterator it2 = list.iterator();
                i = 0;
                while (it2.hasNext()) {
                    if (((androidx.work.Q) it2.next()).b.j.a() && (i = i + 1) < 0) {
                        kotlin.collections.B.o();
                        throw null;
                    }
                }
            } else {
                i = 0;
            }
            i2 += i;
        }
        if (i2 == 0) {
            return;
        }
        androidx.work.impl.model.t tVarU = workDatabase.u();
        tVarU.getClass();
        androidx.room.u uVarA = androidx.room.u.a(0, "Select COUNT(*) FROM workspec WHERE LENGTH(content_uri_triggers)<>0 AND state NOT IN (2, 3, 5)");
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) tVarU.a;
        workDatabase_Impl.b();
        Cursor cursorN = W1.N(workDatabase_Impl, uVarA, false);
        try {
            int i3 = cursorN.moveToFirst() ? cursorN.getInt(0) : 0;
            cursorN.close();
            uVarA.i();
            int i4 = configuration.j;
            if (i3 + i2 > i4) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.r(android.support.v4.media.session.a.w("Too many workers with contentUriTriggers are enqueued:\ncontentUriTrigger workers limit: ", i4, ";\nalready enqueued count: ", ";\ncurrent enqueue operation count: ", i3), i2, ".\nTo address this issue you can: \n1. enqueue less workers or batch some of workers with content uri triggers together;\n2. increase limit via Configuration.Builder.setContentUriTriggerWorkersLimit;\nPlease beware that workers with content uri triggers immediately occupy slots in JobScheduler so no updates to content uris are missed."));
            }
        } catch (Throwable th) {
            cursorN.close();
            uVarA.i();
            throw th;
        }
    }

    public static StringBuilder b(Attributes attributes) {
        StringBuilder sb = new StringBuilder();
        if (attributes != null) {
            for (int i = 0; i < attributes.getLength(); i++) {
                sb.append(' ');
                sb.append(attributes.getLocalName(i));
                sb.append("=\"");
                sb.append(attributes.getValue(i));
                sb.append('\"');
            }
        }
        return sb;
    }
}
