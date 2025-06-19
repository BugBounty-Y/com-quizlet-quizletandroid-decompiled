package com.perimeterx.mobile_sdk.local_data;

import android.app.Application;
import android.content.Context;
import androidx.datastore.core.InterfaceC1076h;
import com.google.android.gms.internal.mlkit_vision_barcode.O6;
import kotlin.jvm.internal.D;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class v implements b {
    public static final /* synthetic */ kotlin.reflect.n[] c;
    public final Application a;
    public final androidx.datastore.b b;

    static {
        D d = new D(v.class, "dataStore", "getDataStore(Landroid/content/Context;)Landroidx/datastore/core/DataStore;");
        K.a.getClass();
        c = new kotlin.reflect.n[]{d};
    }

    public v(Application application) {
        Intrinsics.checkNotNullParameter(application, "application");
        this.a = application;
        this.b = O6.a("com.perimeterx.mobile_sdk", null, 14);
    }

    public static final String h(v vVar, String str, String appId) {
        vVar.getClass();
        StringBuilder sb = new StringBuilder();
        String str2 = com.perimeterx.mobile_sdk.configurations.i.a;
        Intrinsics.checkNotNullParameter(appId, "appId");
        sb.append(com.perimeterx.mobile_sdk.configurations.i.a("com.perimeterx.mobile_sdk.%@", appId));
        sb.append('.');
        sb.append(str);
        return sb.toString();
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final String a(x key, String appId) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        return (String) E.D(kotlin.coroutines.n.a, new f(this, key, appId, null));
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final void b(int i, x key, String appId) throws Throwable {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        E.D(kotlin.coroutines.n.a, new q(this, key, appId, i, null));
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final void c(String value, x key, String appId) throws Throwable {
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        E.D(kotlin.coroutines.n.a, new r(this, key, appId, value, null));
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final void d(boolean z, x key, String appId) throws Throwable {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        E.D(kotlin.coroutines.n.a, new p(this, key, appId, z, null));
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final Boolean e(x key, String appId) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        return (Boolean) E.D(kotlin.coroutines.n.a, new d(this, key, appId, null));
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final Integer f(x key, String appId) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        return (Integer) E.D(kotlin.coroutines.n.a, new e(this, key, appId, null));
    }

    public final InterfaceC1076h g(Context context) {
        return (InterfaceC1076h) this.b.a(context, c[0]);
    }

    @Override // com.perimeterx.mobile_sdk.local_data.b
    public final void a(String appId) throws Throwable {
        Intrinsics.checkNotNullParameter(appId, "appId");
        E.D(kotlin.coroutines.n.a, new o(this, appId, null));
    }
}
