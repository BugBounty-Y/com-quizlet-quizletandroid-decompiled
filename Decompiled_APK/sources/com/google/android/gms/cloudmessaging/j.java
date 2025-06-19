package com.google.android.gms.cloudmessaging;

import android.os.Bundle;
import android.util.Log;

/* loaded from: classes2.dex */
public final class j {
    public final int a;
    public final com.google.android.gms.tasks.f b = new com.google.android.gms.tasks.f();
    public final int c;
    public final Bundle d;
    public final /* synthetic */ int e;

    public j(int i, int i2, Bundle bundle, int i3) {
        this.e = i3;
        this.a = i;
        this.c = i2;
        this.d = bundle;
    }

    public final boolean a() {
        switch (this.e) {
            case 0:
                return true;
            default:
                return false;
        }
    }

    public final void b(zzt zztVar) {
        if (Log.isLoggable("MessengerIpcClient", 3)) {
            toString();
            zztVar.toString();
        }
        this.b.a(zztVar);
    }

    public final String toString() {
        return "Request { what=" + this.c + " id=" + this.a + " oneWay=" + a() + "}";
    }
}
