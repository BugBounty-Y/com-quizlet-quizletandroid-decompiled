package com.quizlet.quizletandroid.ui.common.adapter.presenter;

import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.quizletandroid.ui.group.addclassset.AddClassSetActivity;
import java.util.ArrayList;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements io.reactivex.rxjava3.functions.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ a(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    @Override // io.reactivex.rxjava3.functions.a
    public final void run() {
        switch (this.a) {
            case 0:
                ((e) this.b).f = null;
                ((d) this.c).e((DBTerm) this.d);
                break;
            default:
                AddClassSetActivity addClassSetActivity = (AddClassSetActivity) this.b;
                addClassSetActivity.t.b((ArrayList) this.c, (ArrayList) this.d);
                addClassSetActivity.setResult(-1);
                addClassSetActivity.finish();
                break;
        }
    }
}
