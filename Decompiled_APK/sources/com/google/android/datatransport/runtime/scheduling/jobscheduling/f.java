package com.google.android.datatransport.runtime.scheduling.jobscheduling;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.quizletandroid.databinding.C4601e;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements com.google.android.datatransport.runtime.synchronization.a, com.quizlet.qutils.rx.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ f(int i, Object obj, Object obj2) {
        this.b = obj;
        this.c = obj2;
        this.a = i;
    }

    @Override // com.google.android.datatransport.runtime.synchronization.a
    public Object a() {
        ((i) this.b).d.a((com.google.android.datatransport.runtime.i) this.c, this.a + 1, false);
        return null;
    }

    @Override // com.quizlet.qutils.rx.c
    public void accept(Object obj) {
        DBStudySet dBStudySet = (DBStudySet) obj;
        com.quizlet.quizletandroid.ui.setcreation.activities.h hVar = (com.quizlet.quizletandroid.ui.setcreation.activities.h) this.b;
        com.quizlet.quizletandroid.util.f fVar = hVar.n;
        String str = (String) this.c;
        String strD = fVar.d(str);
        if (org.apache.commons.lang3.e.b(strD)) {
            timber.log.c.b(new IllegalStateException(AbstractC0147y.d("No translated language code could be found for ", str)));
            return;
        }
        int i = this.a;
        if (i == 4321) {
            dBStudySet.setDefLang(str);
            ((C4601e) hVar.k).g.setText(strD);
        } else if (i == 1234) {
            dBStudySet.setWordLang(str);
            ((C4601e) hVar.k).l.setText(strD);
        }
        hVar.o.c(dBStudySet);
    }
}
