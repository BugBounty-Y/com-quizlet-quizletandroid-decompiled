package com.google.firebase.installations;

import android.text.TextUtils;
import java.io.IOException;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ c b;

    public /* synthetic */ b(c cVar, int i) {
        this.a = i;
        this.b = cVar;
    }

    /* JADX WARN: Finally extract failed */
    @Override // java.lang.Runnable
    public final void run() {
        com.google.firebase.installations.local.a aVarO;
        com.google.firebase.installations.local.a aVarG;
        switch (this.a) {
            case 0:
                this.b.a();
                return;
            case 1:
                this.b.a();
                return;
            default:
                c cVar = this.b;
                cVar.getClass();
                Object obj = c.m;
                synchronized (obj) {
                    try {
                        com.google.firebase.h hVar = cVar.a;
                        hVar.a();
                        com.quizlet.data.repository.widget.b bVarA = com.quizlet.data.repository.widget.b.a(hVar.a);
                        try {
                            aVarO = cVar.c.o();
                            if (bVarA != null) {
                                bVarA.s();
                            }
                        } catch (Throwable th) {
                            if (bVarA != null) {
                                bVarA.s();
                            }
                            throw th;
                        }
                    } finally {
                    }
                }
                try {
                    int i = aVarO.b;
                    if (i == 5) {
                        aVarG = cVar.g(aVarO);
                    } else {
                        if (i == 3) {
                            aVarG = cVar.g(aVarO);
                        } else if (!cVar.d.a(aVarO)) {
                            return;
                        } else {
                            aVarG = cVar.b(aVarO);
                        }
                    }
                    synchronized (obj) {
                        try {
                            com.google.firebase.h hVar2 = cVar.a;
                            hVar2.a();
                            com.quizlet.data.repository.widget.b bVarA2 = com.quizlet.data.repository.widget.b.a(hVar2.a);
                            try {
                                cVar.c.k(aVarG);
                                if (bVarA2 != null) {
                                    bVarA2.s();
                                }
                            } catch (Throwable th2) {
                                if (bVarA2 != null) {
                                    bVarA2.s();
                                }
                                throw th2;
                            }
                        } finally {
                        }
                    }
                    synchronized (cVar) {
                        try {
                            if (cVar.k.size() != 0 && !TextUtils.equals(aVarO.a, aVarG.a)) {
                                Iterator it2 = cVar.k.iterator();
                                if (it2.hasNext()) {
                                    if (it2.next() != null) {
                                        throw new ClassCastException();
                                    }
                                    throw null;
                                }
                            }
                        } finally {
                        }
                    }
                    if (aVarG.b == 4) {
                        String str = aVarG.a;
                        synchronized (cVar) {
                            cVar.j = str;
                        }
                    }
                    int i2 = aVarG.b;
                    if (i2 == 5) {
                        cVar.h(new FirebaseInstallationsException());
                        return;
                    } else if (i2 == 2 || i2 == 1) {
                        cVar.h(new IOException("Installation ID could not be validated with the Firebase servers (maybe it was deleted). Firebase Installations will need to create a new Installation ID and auth token. Please retry your last request."));
                        return;
                    } else {
                        cVar.i(aVarG);
                        return;
                    }
                } catch (FirebaseInstallationsException e) {
                    cVar.h(e);
                    return;
                }
        }
    }
}
