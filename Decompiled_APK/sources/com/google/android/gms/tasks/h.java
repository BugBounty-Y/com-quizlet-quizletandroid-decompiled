package com.google.android.gms.tasks;

import java.util.concurrent.ExecutionException;

/* loaded from: classes2.dex */
public final class h implements d, c, b {
    public final Object a = new Object();
    public final int b;
    public final m c;
    public int d;
    public int e;
    public int f;
    public Exception g;
    public boolean h;

    public h(int i, m mVar) {
        this.b = i;
        this.c = mVar;
    }

    public final void a() {
        int i = this.d + this.e + this.f;
        int i2 = this.b;
        if (i == i2) {
            Exception exc = this.g;
            m mVar = this.c;
            if (exc == null) {
                if (this.h) {
                    mVar.s();
                    return;
                } else {
                    mVar.p(null);
                    return;
                }
            }
            int i3 = this.e;
            int length = String.valueOf(i3).length();
            StringBuilder sb = new StringBuilder(String.valueOf(i2).length() + length + 8 + 24);
            sb.append(i3);
            sb.append(" out of ");
            sb.append(i2);
            sb.append(" underlying tasks failed");
            mVar.r(new ExecutionException(sb.toString(), this.g));
        }
    }

    @Override // com.google.android.gms.tasks.b
    public final void j() {
        synchronized (this.a) {
            this.f++;
            this.h = true;
            a();
        }
    }

    @Override // com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        synchronized (this.a) {
            this.d++;
            a();
        }
    }

    @Override // com.google.android.gms.tasks.c
    public final void t(Exception exc) {
        synchronized (this.a) {
            this.e++;
            this.g = exc;
            a();
        }
    }
}
