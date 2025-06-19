package androidx.core.app;

import android.app.Activity;
import android.app.Application;
import android.os.Build;
import android.os.Handler;
import com.android.installreferrer.api.InstallReferrerClient;
import java.lang.reflect.Method;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.core.app.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC1014a implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Activity b;

    public /* synthetic */ RunnableC1014a(int i, Activity activity) {
        this.a = i;
        this.b = activity;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v2, types: [int] */
    /* JADX WARN: Type inference failed for: r5v3 */
    /* JADX WARN: Type inference failed for: r5v6 */
    /* JADX WARN: Type inference failed for: r5v7, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r5v8 */
    /* JADX WARN: Type inference failed for: r6v10 */
    /* JADX WARN: Type inference failed for: r6v11 */
    /* JADX WARN: Type inference failed for: r6v2 */
    /* JADX WARN: Type inference failed for: r6v3 */
    /* JADX WARN: Type inference failed for: r6v4 */
    /* JADX WARN: Type inference failed for: r6v7 */
    /* JADX WARN: Type inference failed for: r6v8, types: [android.os.Handler] */
    /* JADX WARN: Type inference failed for: r6v9 */
    @Override // java.lang.Runnable
    public final void run() {
        Object obj;
        Handler handler;
        C1017d c1017d;
        int i = 3;
        int i2 = 26;
        Application application = null;
        Activity context = this.b;
        switch (this.a) {
            case 0:
                if (context.isFinishing()) {
                    return;
                }
                ?? r5 = Build.VERSION.SDK_INT;
                if (r5 >= 28) {
                    Class cls = AbstractC1018e.a;
                    context.recreate();
                    return;
                }
                Class cls2 = AbstractC1018e.a;
                ?? r6 = 1;
                r6 = 1;
                boolean z = r5 == 26 || r5 == 27;
                Method method = AbstractC1018e.f;
                if ((!z || method != null) && (AbstractC1018e.e != null || AbstractC1018e.d != null)) {
                    try {
                        Object obj2 = AbstractC1018e.c.get(context);
                        if (obj2 != null && (obj = AbstractC1018e.b.get(context)) != null) {
                            Application application2 = context.getApplication();
                            C1017d c1017d2 = new C1017d(context);
                            application2.registerActivityLifecycleCallbacks(c1017d2);
                            Handler handler2 = AbstractC1018e.g;
                            handler2.post(new com.google.common.util.concurrent.d(2, c1017d2, obj2));
                            if (r5 != 26 && r5 != 27) {
                                r6 = 0;
                            }
                            try {
                                if (r6 != 0) {
                                    try {
                                        Boolean bool = Boolean.FALSE;
                                        application = application2;
                                        r5 = c1017d2;
                                        r6 = handler2;
                                        method.invoke(obj, obj2, null, null, 0, bool, null, null, bool, bool);
                                    } catch (Throwable th) {
                                        th = th;
                                        application = application2;
                                        c1017d = c1017d2;
                                        handler = handler2;
                                        handler.post(new androidx.camera.core.impl.utils.futures.h(i, application, c1017d));
                                        throw th;
                                    }
                                } else {
                                    application = application2;
                                    r5 = c1017d2;
                                    r6 = handler2;
                                    context.recreate();
                                }
                                r6.post(new androidx.camera.core.impl.utils.futures.h(i, application, (Object) r5));
                                return;
                            } catch (Throwable th2) {
                                th = th2;
                                c1017d = r5;
                                handler = r6;
                            }
                        }
                    } catch (Throwable unused) {
                    }
                }
                context.recreate();
                return;
            default:
                Intrinsics.checkNotNullParameter(context, "$context");
                if (context.getSharedPreferences(context.getPackageName() + "_preferences", 0).getString("installed_before", null) == null) {
                    androidx.compose.ui.viewinterop.b callback = new androidx.compose.ui.viewinterop.b(i2, new com.snowplowanalytics.core.tracker.b(), context);
                    Intrinsics.checkNotNullParameter(context, "context");
                    Intrinsics.checkNotNullParameter(callback, "callback");
                    InstallReferrerClient installReferrerClientBuild = InstallReferrerClient.newBuilder(context).build();
                    installReferrerClientBuild.startConnection(new com.quizlet.remote.model.user.delete.c(installReferrerClientBuild, callback));
                    return;
                }
                return;
        }
    }
}
