package com.google.android.gms.tasks;

import com.google.android.gms.common.api.internal.w;
import com.google.android.gms.measurement.internal.A0;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class j implements l, d, c, b {
    public final /* synthetic */ int a;
    public final Executor b;
    public final Object c;
    public final Object d;

    public j(Executor executor, b bVar) {
        this.a = 0;
        this.c = new Object();
        this.b = executor;
        this.d = bVar;
    }

    @Override // com.google.android.gms.tasks.l
    public final void a(Task task) {
        switch (this.a) {
            case 0:
                if (task.j()) {
                    synchronized (this.c) {
                        try {
                            if (((b) this.d) != null) {
                                this.b.execute(new w(this, 11));
                            }
                        } finally {
                        }
                    }
                    return;
                }
                return;
            case 1:
                synchronized (this.c) {
                    try {
                        if (((OnCompleteListener) this.d) == null) {
                            return;
                        }
                        this.b.execute(new A0(7, this, task));
                        return;
                    } finally {
                    }
                }
            case 2:
                if (task.l() || task.j()) {
                    return;
                }
                synchronized (this.c) {
                    try {
                        if (((c) this.d) != null) {
                            this.b.execute(new k(0, this, task));
                        }
                    } finally {
                    }
                }
                return;
            case 3:
                if (task.l()) {
                    synchronized (this.c) {
                        try {
                            if (((d) this.d) != null) {
                                this.b.execute(new A0(8, this, task));
                            }
                        } finally {
                        }
                    }
                    return;
                }
                return;
            default:
                this.b.execute(new k(1, this, task));
                return;
        }
    }

    @Override // com.google.android.gms.tasks.b
    public void j() {
        ((m) this.d).s();
    }

    @Override // com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((m) this.d).p(obj);
    }

    @Override // com.google.android.gms.tasks.c
    public void t(Exception exc) {
        ((m) this.d).r(exc);
    }

    public j(Executor executor, OnCompleteListener onCompleteListener) {
        this.a = 1;
        this.c = new Object();
        this.b = executor;
        this.d = onCompleteListener;
    }

    public j(Executor executor, c cVar) {
        this.a = 2;
        this.c = new Object();
        this.b = executor;
        this.d = cVar;
    }

    public j(Executor executor, d dVar) {
        this.a = 3;
        this.c = new Object();
        this.b = executor;
        this.d = dVar;
    }

    public j(Executor executor, e eVar, m mVar) {
        this.a = 4;
        this.b = executor;
        this.c = eVar;
        this.d = mVar;
    }
}
