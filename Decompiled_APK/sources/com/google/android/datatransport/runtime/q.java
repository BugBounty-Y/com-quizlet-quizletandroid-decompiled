package com.google.android.datatransport.runtime;

import android.content.Context;
import androidx.compose.ui.text.input.C;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.Set;

/* loaded from: classes2.dex */
public final class q {
    public static volatile j e;
    public final com.google.android.datatransport.runtime.time.a a;
    public final com.google.android.datatransport.runtime.time.a b;
    public final com.google.android.datatransport.runtime.scheduling.c c;
    public final com.google.android.datatransport.runtime.scheduling.jobscheduling.i d;

    public q(com.google.android.datatransport.runtime.time.a aVar, com.google.android.datatransport.runtime.time.a aVar2, com.google.android.datatransport.runtime.scheduling.c cVar, com.google.android.datatransport.runtime.scheduling.jobscheduling.i iVar, com.google.android.datatransport.runtime.scheduling.jobscheduling.k kVar) {
        this.a = aVar;
        this.b = aVar2;
        this.c = cVar;
        this.d = iVar;
        kVar.getClass();
        kVar.a.execute(new C(kVar, 22));
    }

    public static q a() {
        j jVar = e;
        if (jVar != null) {
            return (q) jVar.f.get();
        }
        throw new IllegalStateException("Not initialized!");
    }

    public static void b(Context context) {
        if (e == null) {
            synchronized (q.class) {
                try {
                    if (e == null) {
                        com.google.firebase.platforminfo.c cVar = new com.google.firebase.platforminfo.c();
                        context.getClass();
                        cVar.a = context;
                        e = cVar.i();
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    public final o c(com.google.android.datatransport.cct.a aVar) {
        byte[] bytes;
        Set setUnmodifiableSet = aVar != null ? Collections.unmodifiableSet(com.google.android.datatransport.cct.a.d) : Collections.singleton(new com.google.android.datatransport.c("proto"));
        com.quizlet.data.repository.set.f fVarA = i.a();
        aVar.getClass();
        fVarA.b = "cct";
        String str = aVar.a;
        String str2 = aVar.b;
        if (str2 == null && str == null) {
            bytes = null;
        } else {
            if (str2 == null) {
                str2 = "";
            }
            bytes = android.support.v4.media.session.a.m("1$", str, "\\", str2).getBytes(Charset.forName("UTF-8"));
        }
        fVarA.c = bytes;
        return new o(setUnmodifiableSet, fVarA.b(), this);
    }
}
