package com.google.firebase.crashlytics.internal.common;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class h {
    public final com.quizlet.data.repository.studysetwithcreatorinclass.g a;
    public final g b;

    public h(com.quizlet.data.repository.studysetwithcreatorinclass.g gVar, com.google.firebase.crashlytics.internal.persistence.c cVar) {
        this.a = gVar;
        this.b = new g(cVar);
    }

    public final void a(String str) {
        g gVar = this.b;
        synchronized (gVar) {
            if (!Objects.equals(gVar.b, str)) {
                g.a(gVar.a, str, gVar.c);
                gVar.b = str;
            }
        }
    }
}
