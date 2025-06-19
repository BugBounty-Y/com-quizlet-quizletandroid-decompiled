package com.quizlet.quizletandroid.ui.setcreation.activities;

import android.content.Intent;
import android.text.TextUtils;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.generated.enums.O1;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ com.quizlet.baseui.base.f c;
    public final /* synthetic */ Object d;

    public /* synthetic */ c(com.quizlet.baseui.base.f fVar, int i, Object obj, int i2) {
        this.a = i2;
        this.c = fVar;
        this.b = i;
        this.d = obj;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        int i;
        int i2 = this.b;
        Object obj2 = this.d;
        com.quizlet.baseui.base.f fVar = this.c;
        DBStudySet dBStudySet = (DBStudySet) obj;
        switch (this.a) {
            case 0:
                d dVar = (d) fVar;
                String str = (String) obj2;
                String strA = dVar.q.a(str);
                if (org.apache.commons.lang3.e.b(strA)) {
                    timber.log.c.b(new IllegalStateException("No translated language code could be found for ".concat(str)));
                    return;
                }
                if (i2 == 4000) {
                    com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = dVar.y;
                    O1 o1 = O1.DEFINITION;
                    iVar.f(o1, str, false);
                    dVar.B.g0(o1, strA);
                    return;
                }
                if (i2 == 3000) {
                    com.quizlet.quizletandroid.ui.setcreation.managers.i iVar2 = dVar.y;
                    O1 o12 = O1.WORD;
                    iVar2.f(o12, str, false);
                    dVar.B.g0(o12, strA);
                    return;
                }
                return;
            case 1:
                h hVar = (h) fVar;
                hVar.getClass();
                if (i2 == 1234) {
                    return;
                }
                Intent intent = (Intent) obj2;
                com.quizlet.quizletandroid.util.j permissionAccess = com.quizlet.quizletandroid.util.j.values()[intent.getIntExtra("current_permission_access", 0)];
                boolean booleanExtra = intent.getBooleanExtra("has_changed_password_use", false);
                boolean booleanExtra2 = intent.getBooleanExtra("changing_set_visibility", false);
                String stringExtra = intent.getStringExtra(DBStudySetFields.Names.PASSWORD);
                if (booleanExtra2) {
                    Intrinsics.checkNotNullParameter(permissionAccess, "permissionAccess");
                    int iOrdinal = permissionAccess.ordinal();
                    if (iOrdinal == 0 || iOrdinal == 1) {
                        i = 0;
                    } else {
                        i = 2;
                        if (iOrdinal != 2) {
                            throw new NoWhenBranchMatchedException();
                        }
                    }
                    dBStudySet.setAccessType(i);
                }
                if (permissionAccess == com.quizlet.quizletandroid.util.j.b) {
                    if (!TextUtils.isEmpty(stringExtra)) {
                        dBStudySet.setPassword(stringExtra);
                    }
                    if (booleanExtra2 && booleanExtra) {
                        dBStudySet.setPasswordUse(true);
                    }
                    if (!booleanExtra2 && booleanExtra) {
                        dBStudySet.setPasswordEdit(true);
                    }
                } else if (booleanExtra2) {
                    dBStudySet.setPasswordUse(false);
                } else {
                    dBStudySet.setPasswordEdit(false);
                }
                hVar.o.c(dBStudySet);
                hVar.l.e("permissions");
                hVar.O(dBStudySet);
                return;
            default:
                new com.google.android.datatransport.runtime.scheduling.jobscheduling.f(i2, (h) fVar, (String) obj2).accept(dBStudySet);
                return;
        }
    }
}
