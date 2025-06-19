package com.quizlet.quizletandroid.ui.setcreation.managers;

import com.google.common.cache.C3912f;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.SuggestionsDataWrapper;
import com.quizlet.api.model.TermContentSuggestions;
import com.quizlet.db.data.models.persisted.DBTerm;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class v {
    public final com.google.common.cache.p a;
    public final com.google.common.cache.p b;
    public final long c;
    public final IQuizletApiClient d;
    public final io.reactivex.rxjava3.core.o e;
    public final io.reactivex.rxjava3.core.o f;
    public com.quizlet.quizletandroid.ui.setcreation.activities.d g;
    public AtomicReference h;
    public AtomicReference i;

    public v(IQuizletApiClient iQuizletApiClient, io.reactivex.rxjava3.core.o oVar, io.reactivex.rxjava3.core.o oVar2, long j) {
        androidx.emoji2.text.n nVar = io.reactivex.rxjava3.internal.functions.d.b;
        this.h = new io.reactivex.rxjava3.disposables.d(nVar, 0);
        this.i = new io.reactivex.rxjava3.disposables.d(nVar, 0);
        this.d = iQuizletApiClient;
        this.e = oVar;
        this.f = oVar2;
        this.c = j;
        C3912f c3912fD = C3912f.d();
        c3912fD.c(100L);
        TimeUnit timeUnit = TimeUnit.MINUTES;
        c3912fD.b(30L, timeUnit);
        this.a = c3912fD.a();
        C3912f c3912fD2 = C3912f.d();
        c3912fD2.c(100L);
        c3912fD2.b(30L, timeUnit);
        this.b = c3912fD2.a();
    }

    public static boolean a(DBTerm dBTerm) {
        if (dBTerm.getWord() == null || dBTerm.getWord().trim().isEmpty()) {
            return false;
        }
        return (dBTerm.getDefinition() == null || dBTerm.getDefinition().length() < 16) && dBTerm.getWord().length() < 76;
    }

    public static boolean b(DBTerm dBTerm) {
        return dBTerm.getWord() != null && dBTerm.getWord().trim().length() >= 5 && dBTerm.getWord().length() < 16;
    }

    public final void c(ApiThreeWrapper apiThreeWrapper, long j, String str, String str2, String str3, String str4, boolean z) {
        if (apiThreeWrapper != null && apiThreeWrapper.getResponses() != null) {
            Iterator it2 = apiThreeWrapper.getResponses().iterator();
            while (it2.hasNext()) {
                SuggestionsDataWrapper suggestionsDataWrapper = (SuggestionsDataWrapper) ((ApiResponse) it2.next()).getDataWrapper();
                if (suggestionsDataWrapper != null) {
                    TermContentSuggestions suggestions = suggestionsDataWrapper.getSuggestions();
                    if (z) {
                        this.a.a.put(new u(str, str3), suggestions);
                        com.quizlet.quizletandroid.ui.setcreation.activities.d dVar = this.g;
                        if (dVar != null) {
                            dVar.P(suggestions);
                            return;
                        }
                        return;
                    }
                    this.b.a.put(new u(str, str3, str2, str4), suggestions);
                    com.quizlet.quizletandroid.ui.setcreation.activities.d dVar2 = this.g;
                    if (dVar2 != null) {
                        dVar2.O(suggestions);
                        return;
                    }
                    return;
                }
            }
        }
        com.quizlet.quizletandroid.ui.setcreation.activities.d dVar3 = this.g;
        if (dVar3 != null) {
            if (z) {
                dVar3.R(j, str3);
            } else {
                dVar3.Q(j, str3, str4);
            }
        }
    }
}
