package androidx.work.impl;

import java.util.ArrayList;
import java.util.concurrent.Callable;

/* renamed from: androidx.work.impl.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class CallableC1432d implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ CallableC1432d(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        switch (this.a) {
            case 0:
                WorkDatabase workDatabase = ((C1433e) this.b).e;
                androidx.work.impl.model.v vVarV = workDatabase.v();
                String str = (String) this.d;
                ((ArrayList) this.c).addAll(vVarV.g(str));
                return workDatabase.u().o(str);
            default:
                com.google.firebase.concurrent.e eVar = (com.google.firebase.concurrent.e) this.b;
                int i = 29;
                return eVar.a.submit(new androidx.credentials.playservices.controllers.c(i, (Callable) this.c, (com.quizlet.data.repository.school.membership.a) this.d));
        }
    }
}
