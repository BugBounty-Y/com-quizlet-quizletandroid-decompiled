package com.quizlet.quizletandroid.ui.common.adapter.viewholder;

import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.generated.enums.O1;

/* loaded from: classes3.dex */
public interface k {
    void a(DBTerm dBTerm, O1 o1, boolean z);

    void b(DBTerm dBTerm);

    void c(DBTerm dBTerm, DBSelectedTerm dBSelectedTerm);
}
