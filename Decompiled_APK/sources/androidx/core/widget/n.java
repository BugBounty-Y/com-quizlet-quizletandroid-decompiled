package androidx.core.widget;

import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Base64;
import android.util.Log;
import android.widget.RemoteViews;
import android.widget.RemoteViewsService;
import com.google.android.gms.internal.mlkit_vision_barcode.A6;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class n implements RemoteViewsService.RemoteViewsFactory {
    public static final k e = new k(new long[0], new RemoteViews[0]);
    public final RemoteViewsCompatService a;
    public final int b;
    public final int c;
    public k d;

    public n(RemoteViewsCompatService mContext, int i, int i2) {
        Intrinsics.checkNotNullParameter(mContext, "mContext");
        this.a = mContext;
        this.b = i;
        this.c = i2;
        this.d = e;
    }

    public final void a() throws PackageManager.NameNotFoundException {
        Long lValueOf;
        RemoteViewsCompatService context = this.a;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("androidx.core.widget.prefs.RemoteViewsCompat", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "context.getSharedPrefere…S_FILENAME, MODE_PRIVATE)");
        StringBuilder sb = new StringBuilder();
        int i = this.b;
        sb.append(i);
        sb.append(':');
        sb.append(this.c);
        k kVar = null;
        String hexString = sharedPreferences.getString(sb.toString(), null);
        if (hexString == null) {
            Log.w("RemoteViewsCompatServic", "No collection items were stored for widget " + i);
        } else {
            l creator = l.c;
            Intrinsics.checkNotNullParameter(hexString, "hexString");
            Intrinsics.checkNotNullParameter(creator, "creator");
            byte[] bArrDecode = Base64.decode(hexString, 0);
            Intrinsics.checkNotNullExpressionValue(bArrDecode, "decode(hexString, Base64.DEFAULT)");
            m mVar = (m) A6.b(bArrDecode, creator);
            if (Intrinsics.b(Build.VERSION.INCREMENTAL, mVar.b)) {
                Intrinsics.checkNotNullParameter(context, "context");
                try {
                    lValueOf = Long.valueOf(Build.VERSION.SDK_INT >= 28 ? androidx.arch.core.executor.d.d(context.getPackageManager().getPackageInfo(context.getPackageName(), 0)) : r0.versionCode);
                } catch (PackageManager.NameNotFoundException e2) {
                    Log.e("RemoteViewsCompatServic", "Couldn't retrieve version code for " + context.getPackageManager(), e2);
                    lValueOf = null;
                }
                if (lValueOf == null) {
                    Log.w("RemoteViewsCompatServic", "Couldn't get version code, not using stored collection items for widget " + i);
                } else if (lValueOf.longValue() != mVar.c) {
                    Log.w("RemoteViewsCompatServic", "App version code has changed, not using stored collection items for widget " + i);
                } else {
                    try {
                        kVar = (k) A6.b(mVar.a, l.b);
                    } catch (Throwable th) {
                        Log.e("RemoteViewsCompatServic", "Unable to deserialize stored collection items for widget " + i, th);
                    }
                }
            } else {
                Log.w("RemoteViewsCompatServic", "Android version code has changed, not using stored collection items for widget " + i);
            }
        }
        if (kVar == null) {
            kVar = e;
        }
        this.d = kVar;
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final int getCount() {
        return this.d.a.length;
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final long getItemId(int i) {
        try {
            return this.d.a[i];
        } catch (ArrayIndexOutOfBoundsException unused) {
            return -1L;
        }
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final /* bridge */ /* synthetic */ RemoteViews getLoadingView() {
        return null;
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final RemoteViews getViewAt(int i) {
        try {
            return this.d.b[i];
        } catch (ArrayIndexOutOfBoundsException unused) {
            return new RemoteViews(this.a.getPackageName(), R.layout.invalid_list_item);
        }
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final int getViewTypeCount() {
        return this.d.d;
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final boolean hasStableIds() {
        return this.d.c;
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final void onCreate() throws PackageManager.NameNotFoundException {
        a();
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final void onDataSetChanged() throws PackageManager.NameNotFoundException {
        a();
    }

    @Override // android.widget.RemoteViewsService.RemoteViewsFactory
    public final void onDestroy() {
    }
}
