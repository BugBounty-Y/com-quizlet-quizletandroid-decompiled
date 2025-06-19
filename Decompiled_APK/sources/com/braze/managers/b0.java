package com.braze.managers;

import android.content.Context;
import androidx.camera.camera2.internal.C0132i;
import androidx.lifecycle.C1247h;
import com.braze.AbstractC1484j;
import com.braze.support.BrazeLogger;
import com.braze.support.ReflectionUtils;
import com.google.android.gms.tasks.Task;
import com.google.firebase.messaging.FirebaseMessaging;
import java.lang.reflect.Method;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b0 {
    public final Context a;
    public final g0 b;
    public final kotlin.k c;
    public final kotlin.k d;

    public b0(Context context, g0 registrationDataProvider) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(registrationDataProvider, "registrationDataProvider");
        this.a = context;
        this.b = registrationDataProvider;
        this.c = kotlin.l.b(new A(27));
        this.d = kotlin.l.b(new D(2));
    }

    public static final String b(String str) {
        return AbstractC1484j.a("Automatically obtained Firebase Cloud Messaging push token: ", str);
    }

    public static final boolean c() {
        return ReflectionUtils.doesMethodExist("com.google.firebase.iid.FirebaseInstanceId", "getToken", String.class, String.class);
    }

    public static final String d(String str) {
        return AbstractC1484j.a("Registering for Firebase Cloud Messaging token using sender id: ", str);
    }

    public static final String e() {
        return "Failed to register for Firebase Cloud Messaging";
    }

    public static final String f() {
        return "Firebase Cloud Messaging 'InstanceId' object could not be invoked. Not registering for Firebase Cloud Messaging.";
    }

    public static final String g() {
        return "Firebase Cloud Messaging 'FirebaseInstanceId.getInstance().getToken()' method could not obtained. Not registering for Firebase Cloud Messaging.";
    }

    public static final String h() {
        return "Could not invoke 'getToken()' Not registering for Firebase Cloud Messaging.";
    }

    public static final String i() {
        return "Failed to get push token via instance id";
    }

    public static final String j() {
        return "Firebase Cloud Messaging 'getInstance' method could not obtained. Not registering for Firebase Cloud Messaging.";
    }

    public static final String k() {
        return "Could not call 'getInstance' method. Not registering for Firebase Cloud Messaging.";
    }

    public final void a(String firebaseSenderId) {
        Intrinsics.checkNotNullParameter(firebaseSenderId, "firebaseSenderId");
        try {
            if (((Boolean) this.d.getValue()).booleanValue()) {
                FirebaseMessaging.getInstance().getToken().addOnCompleteListener(new C0132i(this, 22));
            } else if (((Boolean) this.c.getValue()).booleanValue()) {
                c(firebaseSenderId);
            }
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new D(3), 4, (Object) null);
        }
    }

    public static final String b() {
        return "Firebase Cloud Messaging requires the Google Play Store to be installed.";
    }

    public static final boolean d() {
        return ReflectionUtils.doesMethodExist("com.google.firebase.messaging.FirebaseMessaging", "getToken", new Class[0]);
    }

    public final void c(String str) {
        b0 b0Var;
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.Priority priority = BrazeLogger.Priority.V;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new C(str, 3), 6, (Object) null);
        try {
            Method methodQuietly = ReflectionUtils.getMethodQuietly("com.google.firebase.iid.FirebaseInstanceId", "getInstance", (Class<?>[]) new Class[0]);
            if (methodQuietly == null) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(5), 7, (Object) null);
                return;
            }
            Pair<Boolean, Object> pairInvokeMethodQuietly = ReflectionUtils.invokeMethodQuietly(null, methodQuietly, new Object[0]);
            try {
                if (!((Boolean) pairInvokeMethodQuietly.a).booleanValue()) {
                    BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(6), 7, (Object) null);
                    return;
                }
                Object obj = pairInvokeMethodQuietly.b;
                if (obj == null) {
                    BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new A(28), 7, (Object) null);
                    return;
                }
                Method methodQuietly2 = ReflectionUtils.getMethodQuietly(obj.getClass(), "getToken", (Class<?>[]) new Class[]{String.class, String.class});
                if (methodQuietly2 == null) {
                    BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new A(29), 7, (Object) null);
                    return;
                }
                Pair<Boolean, Object> pairInvokeMethodQuietly2 = ReflectionUtils.invokeMethodQuietly(obj, methodQuietly2, str, FirebaseMessaging.INSTANCE_ID_SCOPE);
                if (!((Boolean) pairInvokeMethodQuietly2.a).booleanValue()) {
                    BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(0), 7, (Object) null);
                    return;
                }
                Object obj2 = pairInvokeMethodQuietly2.b;
                if (obj2 instanceof String) {
                    b0Var = this;
                    try {
                        BrazeLogger.brazelog$default(brazeLogger, (Object) b0Var, priority, (Throwable) null, false, (Function0) new E(obj2, 0), 6, (Object) null);
                        ((l0) b0Var.b).a((String) obj2);
                    } catch (Exception e) {
                        e = e;
                        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) b0Var, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new D(1), 4, (Object) null);
                    }
                }
            } catch (Exception e2) {
                e = e2;
                b0Var = this;
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) b0Var, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new D(1), 4, (Object) null);
            }
        } catch (Exception e3) {
            e = e3;
        }
    }

    public static final void a(b0 b0Var, Task task) {
        Intrinsics.checkNotNullParameter(task, "task");
        if (!task.l()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) b0Var, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C1247h(task, 18), 6, (Object) null);
            return;
        }
        String str = (String) task.h();
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) b0Var, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C(str, 2), 6, (Object) null);
        ((l0) b0Var.b).a(str);
    }

    public static final String a(Task task) {
        return "Fetching registration token failed using FirebaseMessaging instance with default Firebase installation with exception " + task.g();
    }

    public final boolean a() {
        if (com.braze.support.k.b(this.a)) {
            return ((Boolean) this.d.getValue()).booleanValue() || ((Boolean) this.c.getValue()).booleanValue();
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new D(4), 6, (Object) null);
        return false;
    }

    public static final String a(Object obj) {
        return "Automatically obtained Firebase Cloud Messaging token: " + ((String) obj);
    }
}
