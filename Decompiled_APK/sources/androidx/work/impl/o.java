package androidx.work.impl;

import android.content.Context;
import androidx.camera.camera2.internal.m0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class o implements androidx.sqlite.db.d {
    public final /* synthetic */ Context a;

    public /* synthetic */ o(Context context) {
        this.a = context;
    }

    @Override // androidx.sqlite.db.d
    public androidx.sqlite.db.e d(m0 configuration) {
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        Context context = this.a;
        Intrinsics.checkNotNullParameter(context, "context");
        androidx.sqlite.db.c cVar = new androidx.sqlite.db.c(context);
        cVar.b = (String) configuration.d;
        androidx.sqlite.db.b callback = (androidx.sqlite.db.b) configuration.e;
        Intrinsics.checkNotNullParameter(callback, "callback");
        cVar.c = callback;
        cVar.d = true;
        cVar.e = true;
        m0 configuration2 = cVar.a();
        Intrinsics.checkNotNullParameter(configuration2, "configuration");
        return new androidx.sqlite.db.framework.g((Context) configuration2.c, (String) configuration2.d, (androidx.sqlite.db.b) configuration2.e, configuration2.a, configuration2.b);
    }
}
