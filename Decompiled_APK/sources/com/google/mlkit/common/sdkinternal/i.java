package com.google.mlkit.common.sdkinternal;

import android.content.Context;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.ads.C2537qm;
import java.util.UUID;

/* loaded from: classes2.dex */
public class i {
    public static final com.google.firebase.components.a b;
    public final Context a;

    static {
        C2537qm c2537qmB = com.google.firebase.components.a.b(i.class);
        c2537qmB.a(com.google.firebase.components.j.c(f.class));
        c2537qmB.a(com.google.firebase.components.j.c(Context.class));
        c2537qmB.f = new b(20);
        b = c2537qmB.b();
    }

    public i(@NonNull Context context) {
        this.a = context;
    }

    public final synchronized String a() {
        String string = this.a.getSharedPreferences("com.google.mlkit.internal", 0).getString("ml_sdk_instance_id", null);
        if (string != null) {
            return string;
        }
        String string2 = UUID.randomUUID().toString();
        this.a.getSharedPreferences("com.google.mlkit.internal", 0).edit().putString("ml_sdk_instance_id", string2).apply();
        return string2;
    }
}
