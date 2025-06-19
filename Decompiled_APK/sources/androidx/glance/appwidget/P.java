package androidx.glance.appwidget;

import com.google.android.gms.internal.mlkit_vision_barcode.R6;

/* loaded from: classes.dex */
public final class P {
    public static final /* synthetic */ kotlin.reflect.n[] a;

    static {
        kotlin.jvm.internal.D d = new kotlin.jvm.internal.D(P.class, "appManagerDataStore", "getAppManagerDataStore(Landroid/content/Context;)Landroidx/datastore/core/DataStore;");
        kotlin.jvm.internal.K.a.getClass();
        a = new kotlin.reflect.n[]{d};
    }

    public static final androidx.datastore.preferences.core.f a(P p, String str) {
        p.getClass();
        return R6.d("provider:" + str);
    }
}
