package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import com.quizlet.features.emailconfirmation.ui.activities.EmailConfirmationActivity;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class T {
    public static androidx.camera.core.impl.utils.executor.a a() {
        if (androidx.camera.core.impl.utils.executor.a.b != null) {
            return androidx.camera.core.impl.utils.executor.a.b;
        }
        synchronized (androidx.camera.core.impl.utils.executor.a.class) {
            try {
                if (androidx.camera.core.impl.utils.executor.a.b == null) {
                    androidx.camera.core.impl.utils.executor.a.b = new androidx.camera.core.impl.utils.executor.a(0);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return androidx.camera.core.impl.utils.executor.a.b;
    }

    public static Intent b(Context context, Intent[] redirectIntentsAfterConfirmed) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(redirectIntentsAfterConfirmed, "redirectIntentsAfterConfirmed");
        Intent intent = new Intent(context, (Class<?>) EmailConfirmationActivity.class);
        intent.putExtra("extraRedirectIntents", redirectIntentsAfterConfirmed);
        return intent;
    }

    public static androidx.camera.core.impl.utils.executor.g c() {
        if (androidx.camera.core.impl.utils.executor.g.c != null) {
            return androidx.camera.core.impl.utils.executor.g.c;
        }
        synchronized (androidx.camera.core.impl.utils.executor.g.class) {
            try {
                if (androidx.camera.core.impl.utils.executor.g.c == null) {
                    androidx.camera.core.impl.utils.executor.g.c = new androidx.camera.core.impl.utils.executor.g();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return androidx.camera.core.impl.utils.executor.g.c;
    }

    public static androidx.camera.core.impl.utils.executor.h d() {
        if (androidx.camera.core.impl.utils.executor.h.c != null) {
            return androidx.camera.core.impl.utils.executor.h.c;
        }
        synchronized (androidx.camera.core.impl.utils.executor.h.class) {
            try {
                if (androidx.camera.core.impl.utils.executor.h.c == null) {
                    androidx.camera.core.impl.utils.executor.h.c = new androidx.camera.core.impl.utils.executor.h(0);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return androidx.camera.core.impl.utils.executor.h.c;
    }

    public static androidx.camera.core.impl.utils.executor.e e() {
        if (androidx.camera.core.impl.utils.executor.i.a != null) {
            return androidx.camera.core.impl.utils.executor.i.a;
        }
        synchronized (androidx.camera.core.impl.utils.executor.i.class) {
            try {
                if (androidx.camera.core.impl.utils.executor.i.a == null) {
                    androidx.camera.core.impl.utils.executor.i.a = new androidx.camera.core.impl.utils.executor.e(new Handler(Looper.getMainLooper()));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return androidx.camera.core.impl.utils.executor.i.a;
    }

    public static ArrayList f(com.quizlet.remote.mapper.base.b bVar, List remotes) {
        Intrinsics.checkNotNullParameter(remotes, "remotes");
        return S.f(bVar, remotes);
    }

    public static ArrayList g(com.quizlet.remote.mapper.base.b bVar, List datas) {
        Intrinsics.checkNotNullParameter(datas, "datas");
        Intrinsics.checkNotNullParameter(datas, "datas");
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(datas, 10));
        Iterator it2 = datas.iterator();
        while (it2.hasNext()) {
            arrayList.add(bVar.h(it2.next()));
        }
        return arrayList;
    }
}
