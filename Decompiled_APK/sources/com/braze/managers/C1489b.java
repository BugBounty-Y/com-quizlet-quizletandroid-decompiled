package com.braze.managers;

import android.content.Context;
import androidx.lifecycle.C1247h;
import com.amazon.device.messaging.ADM;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.braze.managers.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1489b {
    public static final C1488a c = new C1488a();
    public final Context a;
    public final g0 b;

    public C1489b(Context context, g0 admRegistrationDataProvider) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(admRegistrationDataProvider, "admRegistrationDataProvider");
        this.a = context;
        this.b = admRegistrationDataProvider;
    }

    public static final String b() {
        return "Registering with ADM server...";
    }

    public final void a() {
        if (((l0) this.b).b() != null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new C1247h(this, 17), 6, (Object) null);
            l0 l0Var = (l0) this.b;
            l0Var.a(l0Var.b());
        } else {
            ADM adm = new ADM(this.a);
            if (adm.isSupported()) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new A(26), 6, (Object) null);
                adm.startRegister();
            }
        }
    }

    public static final String a(C1489b c1489b) {
        return "The device is already registered with the ADM server and is eligible to receive ADM messages.ADM registration id: " + ((l0) c1489b.b).b();
    }
}
