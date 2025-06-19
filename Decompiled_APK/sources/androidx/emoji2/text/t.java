package androidx.emoji2.text;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Handler;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.text.input.C;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.X6;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public final class t implements i {
    public final Context a;
    public final androidx.core.provider.d b;
    public final com.quizlet.shared.usecase.srs.a c;
    public final Object d;
    public Handler e;
    public ThreadPoolExecutor f;
    public ThreadPoolExecutor g;
    public X6 h;

    public t(Context context, androidx.core.provider.d dVar) {
        com.quizlet.shared.usecase.srs.a aVar = u.d;
        this.d = new Object();
        AbstractC3242q6.g(context, "Context cannot be null");
        this.a = context.getApplicationContext();
        this.b = dVar;
        this.c = aVar;
    }

    @Override // androidx.emoji2.text.i
    public final void a(X6 x6) {
        synchronized (this.d) {
            this.h = x6;
        }
        synchronized (this.d) {
            try {
                if (this.h == null) {
                    return;
                }
                if (this.f == null) {
                    ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(0, 1, 15L, TimeUnit.SECONDS, new LinkedBlockingDeque(), new ThreadFactoryC1119a("emojiCompat"));
                    threadPoolExecutor.allowCoreThreadTimeOut(true);
                    this.g = threadPoolExecutor;
                    this.f = threadPoolExecutor;
                }
                this.f.execute(new C(this, 6));
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void b() {
        synchronized (this.d) {
            try {
                this.h = null;
                Handler handler = this.e;
                if (handler != null) {
                    handler.removeCallbacks(null);
                }
                this.e = null;
                ThreadPoolExecutor threadPoolExecutor = this.g;
                if (threadPoolExecutor != null) {
                    threadPoolExecutor.shutdown();
                }
                this.f = null;
                this.g = null;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final androidx.core.provider.h c() {
        try {
            com.quizlet.shared.usecase.srs.a aVar = this.c;
            Context context = this.a;
            androidx.core.provider.d dVar = this.b;
            aVar.getClass();
            Object[] objArr = {dVar};
            ArrayList arrayList = new ArrayList(1);
            Object obj = objArr[0];
            Objects.requireNonNull(obj);
            arrayList.add(obj);
            com.android.billingclient.api.s sVarA = androidx.core.provider.c.a(context, Collections.unmodifiableList(arrayList));
            int i = sVarA.b;
            if (i != 0) {
                throw new RuntimeException(AbstractC0147y.c(i, "fetchFonts failed (", ")"));
            }
            androidx.core.provider.h[] hVarArr = (androidx.core.provider.h[]) ((List) sVarA.c).get(0);
            if (hVarArr == null || hVarArr.length == 0) {
                throw new RuntimeException("fetchFonts failed (empty result)");
            }
            return hVarArr[0];
        } catch (PackageManager.NameNotFoundException e) {
            throw new RuntimeException("provider not found", e);
        }
    }
}
