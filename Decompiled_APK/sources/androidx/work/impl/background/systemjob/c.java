package androidx.work.impl.background.systemjob;

import android.content.ComponentName;
import android.content.Context;
import androidx.work.B;
import androidx.work.z;

/* loaded from: classes.dex */
public final class c {
    public final ComponentName a;
    public final B b;
    public final boolean c;

    static {
        z.e("SystemJobInfoConverter");
    }

    public c(Context context, B b, boolean z) {
        this.b = b;
        this.a = new ComponentName(context.getApplicationContext(), (Class<?>) SystemJobService.class);
        this.c = z;
    }
}
