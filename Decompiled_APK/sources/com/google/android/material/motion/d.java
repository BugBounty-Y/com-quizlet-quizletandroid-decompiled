package com.google.android.material.motion;

import android.window.BackEvent;
import android.window.OnBackAnimationCallback;
import androidx.activity.C0030b;

/* loaded from: classes2.dex */
public final class d implements OnBackAnimationCallback {
    public final /* synthetic */ b a;
    public final /* synthetic */ e b;

    public d(e eVar, b bVar) {
        this.b = eVar;
        this.a = bVar;
    }

    public final void onBackCancelled() {
        if (this.b.a != null) {
            this.a.d();
        }
    }

    public final void onBackInvoked() {
        this.a.c();
    }

    public final void onBackProgressed(BackEvent backEvent) {
        if (this.b.a != null) {
            this.a.b(new C0030b(backEvent));
        }
    }

    public final void onBackStarted(BackEvent backEvent) {
        if (this.b.a != null) {
            this.a.a(new C0030b(backEvent));
        }
    }
}
