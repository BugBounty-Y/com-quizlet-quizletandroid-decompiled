package com.google.android.gms.internal.appset;

import android.content.Context;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.m;

/* loaded from: classes2.dex */
public final class g implements com.google.android.gms.appset.a {
    public final f a;
    public final e b;

    public g(Context context) {
        e eVar;
        this.a = new f(context, com.google.android.gms.common.c.b);
        synchronized (e.class) {
            try {
                if (e.e == null) {
                    e.e = new e(context.getApplicationContext());
                }
                eVar = e.e;
            } catch (Throwable th) {
                throw th;
            }
        }
        this.b = eVar;
    }

    @Override // com.google.android.gms.appset.a
    public final Task b() {
        Task taskB = this.a.b();
        com.quizlet.data.repository.school.membership.a aVar = new com.quizlet.data.repository.school.membership.a(this, 18);
        m mVar = (m) taskB;
        mVar.getClass();
        return mVar.f(com.google.android.gms.tasks.g.a, aVar);
    }
}
