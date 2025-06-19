package com.iab.omid.library.amazon.walking.async;

import android.os.AsyncTask;

/* loaded from: classes2.dex */
public abstract class a extends AsyncTask {
    public com.quizlet.data.repository.folderset.c a;
    public final com.quizlet.data.repository.qclass.c b;

    public a(com.quizlet.data.repository.qclass.c cVar) {
        this.b = cVar;
    }

    @Override // android.os.AsyncTask
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public void onPostExecute(String str) {
        com.quizlet.data.repository.folderset.c cVar = this.a;
        if (cVar != null) {
            cVar.d = null;
            cVar.k();
        }
    }
}
