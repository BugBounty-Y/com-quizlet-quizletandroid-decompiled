package com.pubmatic.sdk.common.utility;

import android.os.Handler;
import android.os.Looper;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public class l {

    @NonNull
    private final k a;

    @NonNull
    private final Handler b = new Handler(Looper.getMainLooper());

    @NonNull
    private final ArrayList<Runnable> c = new ArrayList<>(1);
    private Runnable d;

    public class a implements Runnable {
        public a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            l.this.a.onTimeout();
        }
    }

    public class b implements Runnable {
        final /* synthetic */ long a;

        public b(long j) {
            this.a = j;
        }

        @Override // java.lang.Runnable
        public void run() {
            l.this.a.onTimeout();
            if (l.this.c.contains(this)) {
                l.this.a(this.a, this);
            }
        }
    }

    public l(@NonNull k kVar) {
        this.a = kVar;
    }

    public void cancel() {
        Runnable runnable = this.d;
        if (runnable != null) {
            this.c.remove(runnable);
            this.b.removeCallbacks(this.d);
        }
        this.d = null;
    }

    public boolean start(long j) {
        cancel();
        a aVar = new a();
        this.d = aVar;
        return a(j, aVar);
    }

    public boolean startAtFixedRate(long j, long j2) {
        cancel();
        b bVar = new b(j2);
        this.d = bVar;
        return a(j, bVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean a(long j, @NonNull Runnable runnable) {
        if (j < 0) {
            POBLog.error("POBTimeoutHandler", "Can not start timeout task as provided delay is invalid.", new Object[0]);
            return false;
        }
        this.c.add(runnable);
        return this.b.postDelayed(runnable, j);
    }
}
