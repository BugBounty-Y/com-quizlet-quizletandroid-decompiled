package com.quizlet.data.interactor.folderwithcreator;

import com.quizlet.data.model.CreatedFolderWithCreator;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class i implements io.reactivex.rxjava3.functions.h {
    public static final i a = new i();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        List list = (List) obj;
        ArrayList arrayListM = assistantMode.refactored.a.m("folders", list);
        for (Object obj2 : list) {
            if (!((CreatedFolderWithCreator) obj2).a.k()) {
                arrayListM.add(obj2);
            }
        }
        return arrayListM;
    }
}
