package com.quizlet.quizletandroid.ui.group.addclassset.data;

import com.quizlet.db.data.models.persisted.DBGroupSet;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes3.dex */
public final class a implements h {
    public static final a a = new a();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        List list = (List) obj;
        ArrayList arrayListM = assistantMode.refactored.a.m("classSets", list);
        for (Object obj2 : list) {
            if (((DBGroupSet) obj2).getFolderId() == null) {
                arrayListM.add(obj2);
            }
        }
        return arrayListM;
    }
}
