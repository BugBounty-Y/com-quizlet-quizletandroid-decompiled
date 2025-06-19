package com.google.firebase.messaging;

import android.content.Context;
import android.content.Intent;
import android.util.Base64;
import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;

/* loaded from: classes2.dex */
public class h {
    public static final Object c = new Object();
    public static G d;
    public final Context a;
    public final androidx.arch.core.executor.a b = new androidx.arch.core.executor.a(1);

    public h(Context context) {
        this.a = context;
    }

    public static Task a(Context context, Intent intent, boolean z) {
        G g;
        Log.isLoggable("FirebaseMessaging", 3);
        synchronized (c) {
            try {
                if (d == null) {
                    d = new G(context);
                }
                g = d;
            } finally {
            }
        }
        if (!z) {
            return g.b(intent).e(new androidx.arch.core.executor.a(1), new com.google.firebase.components.n(18));
        }
        if (u.d().f(context)) {
            synchronized (D.b) {
                try {
                    if (D.c == null) {
                        com.google.android.gms.stats.a aVar = new com.google.android.gms.stats.a(context, "wake:com.google.firebase.iid.WakeLockHolder");
                        D.c = aVar;
                        synchronized (aVar.a) {
                            aVar.g = true;
                        }
                    }
                    boolean booleanExtra = intent.getBooleanExtra("com.google.firebase.iid.WakeLockHolder.wakefulintent", false);
                    intent.putExtra("com.google.firebase.iid.WakeLockHolder.wakefulintent", true);
                    if (!booleanExtra) {
                        D.c.a(D.a);
                    }
                    g.b(intent).addOnCompleteListener(new com.google.android.material.search.a(intent, 11));
                } finally {
                }
            }
        } else {
            g.b(intent);
        }
        return S3.i(-1);
    }

    public final Task b(final Intent intent) {
        String stringExtra = intent.getStringExtra("gcm.rawData64");
        if (stringExtra != null) {
            intent.putExtra("rawData", Base64.decode(stringExtra, 0));
            intent.removeExtra("gcm.rawData64");
        }
        final Context context = this.a;
        boolean z = context.getApplicationInfo().targetSdkVersion >= 26;
        final boolean z2 = (intent.getFlags() & 268435456) != 0;
        if (z && !z2) {
            return a(context, intent, z2);
        }
        androidx.arch.core.executor.a aVar = this.b;
        return S3.g(aVar, new androidx.work.impl.A(3, context, intent)).f(aVar, new com.google.android.gms.tasks.a() { // from class: com.google.firebase.messaging.g
            @Override // com.google.android.gms.tasks.a
            public final Object h(Task task) {
                if (((Integer) task.h()).intValue() != 402) {
                    return task;
                }
                return h.a(context, intent, z2).e(new androidx.arch.core.executor.a(1), new com.google.firebase.components.n(17));
            }
        });
    }
}
