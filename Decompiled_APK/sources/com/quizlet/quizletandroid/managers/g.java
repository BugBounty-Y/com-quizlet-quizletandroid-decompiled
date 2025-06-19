package com.quizlet.quizletandroid.managers;

import com.google.common.collect.C;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.model.CountryInformation;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.eventlogger.events.CurrentUserEvent;
import com.quizlet.eventlogger.events.UserLogoutEvent;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Locale;

/* loaded from: classes3.dex */
public final class g implements com.quizlet.login.common.util.b {
    public static final C g = C.d(1, new Object[]{"de", 14}, null);
    public final IQuizletApiClient a;
    public final io.reactivex.rxjava3.core.o b;
    public final io.reactivex.rxjava3.core.o c;
    public CurrentUserEvent d;
    public CountryInformation e;
    public final ArrayList f = new ArrayList();

    public g(com.squareup.otto.c cVar, IQuizletApiClient iQuizletApiClient, io.reactivex.rxjava3.core.o oVar, io.reactivex.rxjava3.core.o oVar2) throws IllegalAccessException, SecurityException, IllegalArgumentException {
        this.a = iQuizletApiClient;
        this.b = oVar;
        this.c = oVar2;
        cVar.d(this);
    }

    public static void c(f fVar, DBUser dBUser) {
        e eVar = dBUser == null ? e.a : dBUser.getIsUnderAge() ? e.b : e.c;
        timber.log.c.a.a("Reporting coppa state: %s", eVar);
        fVar.a(eVar);
    }

    public final void a(f fVar) {
        CurrentUserEvent currentUserEvent = this.d;
        if (currentUserEvent == null || !currentUserEvent.c) {
            c(fVar, null);
            return;
        }
        timber.log.a aVar = timber.log.c.a;
        aVar.a("User is logged in", new Object[0]);
        if (this.d.getCurrentUser() != null) {
            aVar.a("Logged in user available", new Object[0]);
            c(fVar, this.d.getCurrentUser());
        } else {
            aVar.a("Logged in user available", new Object[0]);
            this.f.add(fVar);
        }
    }

    public final int b() {
        CountryInformation countryInformation = this.e;
        if (countryInformation != null) {
            return countryInformation.getUnderAgeCutoff();
        }
        String lowerCase = Locale.getDefault().getCountry().toLowerCase();
        C c = g;
        if (c.containsKey(lowerCase)) {
            return ((Integer) c.get(lowerCase)).intValue();
        }
        return 13;
    }

    @com.squareup.otto.i
    public void currentUser(CurrentUserEvent currentUserEvent) {
        this.d = currentUserEvent;
        if (currentUserEvent.getCurrentUser() != null) {
            ArrayList arrayList = this.f;
            if (arrayList.size() > 0) {
                timber.log.c.a.a("Logged in user available", new Object[0]);
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    c((f) it2.next(), this.d.getCurrentUser());
                }
                arrayList.clear();
            }
        }
    }

    @com.squareup.otto.i
    public void userLogOut(UserLogoutEvent userLogoutEvent) {
        this.d = null;
    }
}
