package com.quizlet.android.migrator.tools;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.runtime.AbstractC0772a;
import com.google.firebase.messaging.p;
import com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper;
import java.util.LinkedHashSet;

/* loaded from: classes2.dex */
public final class b extends AbstractC0772a {
    public final void o(Class cls, String str, String str2, String str3, String str4) {
        if (((LinkedHashSet) ((p) this.c).b).contains(str)) {
            String strG = AbstractC0147y.g(AbstractC0147y.h("UPDATE `", str, "` SET ", str2, " = "), str3, str4 == null ? "" : " WHERE ".concat(str4), ";");
            timber.log.c.a.a("%s (%d records updated)", strG, Integer.valueOf(((OrmLiteSqliteOpenHelper) this.a).getDao(cls).updateRaw(strG, new String[0])));
        }
    }
}
