package com.quizlet.quizletandroid.ui.setcreation.managers;

import android.os.Handler;
import android.os.Looper;
import com.google.common.cache.C3912f;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.generated.enums.O1;
import io.reactivex.rxjava3.internal.operators.observable.C4902v;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;

/* loaded from: classes3.dex */
public final class k {
    public static final androidx.core.util.c j = new androidx.core.util.c("", "");
    public final long a;
    public final long b;
    public final IQuizletApiClient c;
    public final io.reactivex.rxjava3.core.o d;
    public final io.reactivex.rxjava3.core.o e;
    public final com.google.common.cache.p f;
    public final io.reactivex.rxjava3.subjects.d g;
    public final io.reactivex.rxjava3.subjects.d h;
    public com.quizlet.quizletandroid.ui.setcreation.activities.d i;

    public k(IQuizletApiClient iQuizletApiClient, io.reactivex.rxjava3.core.o oVar, io.reactivex.rxjava3.core.o oVar2, long j2, long j3) {
        this.c = iQuizletApiClient;
        this.d = oVar;
        this.e = oVar2;
        this.a = j2;
        this.b = j3;
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        this.h = dVarZ;
        io.reactivex.rxjava3.subjects.d dVarZ2 = io.reactivex.rxjava3.subjects.d.z();
        this.g = dVarZ2;
        C3912f c3912fD = C3912f.d();
        c3912fD.c(200L);
        c3912fD.b(30L, TimeUnit.MINUTES);
        this.f = c3912fD.a();
        TimeUnit timeUnit = TimeUnit.SECONDS;
        io.reactivex.rxjava3.core.o oVar3 = io.reactivex.rxjava3.schedulers.e.b;
        C4902v c4902vH = dVarZ2.h(1L, timeUnit, oVar3);
        final int i = 0;
        io.reactivex.rxjava3.functions.d dVar = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.managers.j
            public final /* synthetic */ k b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                List list = (List) obj;
                switch (i) {
                    case 0:
                        k kVar = this.b;
                        kVar.getClass();
                        kVar.a(O1.WORD, list);
                        break;
                    default:
                        k kVar2 = this.b;
                        kVar2.getClass();
                        kVar2.a(O1.DEFINITION, list);
                        break;
                }
            }
        };
        com.quizlet.billing.subscriptions.c cVar = new com.quizlet.billing.subscriptions.c(2);
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        c4902vH.u(dVar, cVar, bVar);
        C4902v c4902vH2 = dVarZ.h(1L, timeUnit, oVar3);
        final int i2 = 1;
        c4902vH2.u(new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.managers.j
            public final /* synthetic */ k b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                List list = (List) obj;
                switch (i2) {
                    case 0:
                        k kVar = this.b;
                        kVar.getClass();
                        kVar.a(O1.WORD, list);
                        break;
                    default:
                        k kVar2 = this.b;
                        kVar2.getClass();
                        kVar2.a(O1.DEFINITION, list);
                        break;
                }
            }
        }, new com.quizlet.billing.subscriptions.c(2), bVar);
    }

    public final void a(O1 o1, List list) {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            String strSubstring = (String) it2.next();
            if (strSubstring != null) {
                if (strSubstring.length() > 100) {
                    strSubstring = strSubstring.substring(0, 100);
                }
                arrayList.add(strSubstring);
            }
        }
        String string = arrayList.isEmpty() ? null : new JSONArray((Collection) arrayList).toString();
        if (string != null) {
            androidx.core.util.c cVar = (androidx.core.util.c) this.f.a(string);
            if (cVar == null) {
                this.c.r(this.b, this.a, string).l(this.d).h(this.e).i(new com.quizlet.infra.legacysyncengine.net.request.e(this, o1, string, 3), new com.quizlet.billing.subscriptions.c(6));
            } else if (!j.equals(cVar)) {
                new Handler(Looper.getMainLooper()).post(new androidx.camera.camera2.internal.compat.b(this, o1, (String) cVar.a, (String) cVar.b, 11));
            }
        }
    }
}
