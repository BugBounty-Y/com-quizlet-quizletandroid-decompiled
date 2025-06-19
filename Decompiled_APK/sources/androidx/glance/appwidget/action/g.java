package androidx.glance.appwidget.action;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcelable;
import android.os.StrictMode;
import androidx.compose.animation.core.O;
import androidx.glance.appwidget.N0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3216n7;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class g {
    public static final androidx.glance.action.c a = new androidx.glance.action.c("android.widget.extra.CHECKED");

    public static e a(Intent intent) {
        return new e(intent, AbstractC3216n7.c((androidx.glance.action.d[]) Arrays.copyOf(new androidx.glance.action.d[0], 0)));
    }

    public static final Uri b(N0 n0, int i, int i2, String str) {
        String str2;
        Uri.Builder builder = new Uri.Builder();
        builder.scheme("glance-action");
        if (i2 == 1) {
            str2 = "ACTIVITY";
        } else if (i2 == 2) {
            str2 = "BROADCAST";
        } else if (i2 == 3) {
            str2 = "SERVICE";
        } else if (i2 == 4) {
            str2 = "FOREGROUND_SERVICE";
        } else {
            if (i2 != 5) {
                throw null;
            }
            str2 = "CALLBACK";
        }
        builder.path(str2);
        builder.appendQueryParameter("appWidgetId", String.valueOf(n0.b));
        builder.appendQueryParameter("viewId", String.valueOf(i));
        builder.appendQueryParameter("viewSize", androidx.compose.ui.unit.g.c(n0.j));
        builder.appendQueryParameter("extraData", str);
        if (n0.f) {
            builder.appendQueryParameter("lazyCollection", String.valueOf(n0.k));
            builder.appendQueryParameter("lazeViewItem", String.valueOf(-1));
        }
        return builder.build();
    }

    public static final Intent c(androidx.glance.action.a aVar, N0 n0, int i, Function1 function1) {
        if (aVar instanceof e) {
            e eVar = (e) aVar;
            Intent intentE = e(eVar, (androidx.glance.action.f) function1.invoke(eVar.b));
            if (intentE.getData() == null) {
                intentE.setData(b(n0, i, 5, ""));
            }
            return intentE;
        }
        if (!(aVar instanceof androidx.glance.action.e)) {
            throw new IllegalStateException(("Cannot create fill-in Intent for action type: " + aVar).toString());
        }
        ComponentName componentName = n0.n;
        if (componentName == null) {
            throw new IllegalArgumentException("In order to use LambdaAction, actionBroadcastReceiver must be provided");
        }
        Intent intentPutExtra = new Intent().setComponent(componentName).setAction("ACTION_TRIGGER_LAMBDA").putExtra("EXTRA_ACTION_KEY", (String) null).putExtra("EXTRA_APPWIDGET_ID", n0.b);
        Intent intent = new Intent(n0.a, (Class<?>) InvisibleActionTrampolineActivity.class);
        intent.setData(b(n0, i, 2, ""));
        intent.putExtra("ACTION_TYPE", "BROADCAST");
        intent.putExtra("ACTION_INTENT", intentPutExtra);
        return intent;
    }

    public static final PendingIntent d(androidx.glance.action.a aVar, N0 n0, int i, Function1 function1) {
        boolean z = aVar instanceof e;
        Context context = n0.a;
        if (z) {
            e eVar = (e) aVar;
            Intent intentE = e(eVar, (androidx.glance.action.f) function1.invoke(eVar.b));
            if (intentE.getData() == null) {
                intentE.setData(b(n0, i, 5, ""));
            }
            Unit unit = Unit.a;
            return PendingIntent.getActivity(context, 0, intentE, 201326592, null);
        }
        if (!(aVar instanceof androidx.glance.action.e)) {
            throw new IllegalStateException(("Cannot create PendingIntent for action type: " + aVar).toString());
        }
        ComponentName componentName = n0.n;
        if (componentName == null) {
            throw new IllegalArgumentException("In order to use LambdaAction, actionBroadcastReceiver must be provided");
        }
        Intent intentPutExtra = new Intent().setComponent(componentName).setAction("ACTION_TRIGGER_LAMBDA").putExtra("EXTRA_ACTION_KEY", (String) null).putExtra("EXTRA_APPWIDGET_ID", n0.b);
        intentPutExtra.setData(b(n0, i, 5, null));
        Unit unit2 = Unit.a;
        return PendingIntent.getBroadcast(context, 0, intentPutExtra, 201326592);
    }

    public static final Intent e(e eVar, androidx.glance.action.f fVar) {
        if (!(eVar instanceof e)) {
            throw new IllegalStateException(("Action type not defined in app widget package: " + eVar).toString());
        }
        Map mapUnmodifiableMap = Collections.unmodifiableMap(fVar.a);
        ArrayList arrayList = new ArrayList(mapUnmodifiableMap.size());
        for (Map.Entry entry : mapUnmodifiableMap.entrySet()) {
            arrayList.add(new Pair(((androidx.glance.action.c) entry.getKey()).a, entry.getValue()));
        }
        Pair[] pairArr = (Pair[]) arrayList.toArray(new Pair[0]);
        Bundle bundleA = AbstractC3206m6.a((Pair[]) Arrays.copyOf(pairArr, pairArr.length));
        Intent intent = eVar.a;
        intent.putExtras(bundleA);
        return intent;
    }

    public static final void f(Activity activity, Intent intent) {
        Parcelable parcelableExtra = intent.getParcelableExtra("ACTION_INTENT");
        if (parcelableExtra == null) {
            throw new IllegalArgumentException("List adapter activity trampoline invoked without specifying target intent.");
        }
        Intent intent2 = (Intent) parcelableExtra;
        if (intent.hasExtra("android.widget.extra.CHECKED")) {
            intent2.putExtra("android.widget.extra.CHECKED", intent.getBooleanExtra("android.widget.extra.CHECKED", false));
        }
        String stringExtra = intent.getStringExtra("ACTION_TYPE");
        if (stringExtra == null) {
            throw new IllegalArgumentException("List adapter activity trampoline invoked without trampoline type");
        }
        O o = new O(stringExtra, activity, intent2, intent.getBundleExtra("ACTIVITY_OPTIONS"), 8);
        StrictMode.VmPolicy vmPolicy = StrictMode.getVmPolicy();
        StrictMode.setVmPolicy(Build.VERSION.SDK_INT >= 31 ? f.a.a(new StrictMode.VmPolicy.Builder(vmPolicy)).build() : new StrictMode.VmPolicy.Builder().build());
        o.invoke();
        StrictMode.setVmPolicy(vmPolicy);
        activity.finish();
    }
}
