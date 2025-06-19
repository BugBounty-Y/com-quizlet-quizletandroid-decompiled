package androidx.work.impl.background.systemalarm;

import android.content.Context;
import androidx.work.B;
import androidx.work.impl.constraints.m;
import androidx.work.z;

/* loaded from: classes.dex */
public final class d {
    public final Context a;
    public final B b;
    public final int c;
    public final m d;

    static {
        z.e("ConstraintsCmdHandler");
    }

    public d(Context context, B b, int i, h hVar) {
        this.a = context;
        this.b = b;
        this.c = i;
        this.d = new m(hVar.e.j);
    }
}
