package leakcanary.internal;

import android.app.Application;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Looper;
import java.util.EnumSet;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;
import leakcanary.w;

@Metadata
/* loaded from: classes3.dex */
public final class PlumberInstaller extends ContentProvider {
    @Override // android.content.ContentProvider
    public final int delete(Uri uri, String str, String[] strArr) {
        Intrinsics.f(uri, "uri");
        return 0;
    }

    @Override // android.content.ContentProvider
    public final String getType(Uri uri) {
        Intrinsics.f(uri, "uri");
        return null;
    }

    @Override // android.content.ContentProvider
    public final Uri insert(Uri uri, ContentValues contentValues) {
        Intrinsics.f(uri, "uri");
        return null;
    }

    @Override // android.content.ContentProvider
    public final boolean onCreate() {
        Context context = getContext();
        if (context == null) {
            Intrinsics.l();
        }
        Intrinsics.c(context, "context!!");
        Context applicationContext = context.getApplicationContext();
        if (applicationContext == null) {
            throw new TypeCastException("null cannot be cast to non-null type android.app.Application");
        }
        Application application = (Application) applicationContext;
        w[] wVarArr = w.b;
        EnumSet<w> enumSetAllOf = EnumSet.allOf(w.class);
        Intrinsics.c(enumSetAllOf, "EnumSet.allOf(AndroidLeakFixes::class.java)");
        u uVar = d.a;
        Looper mainLooper = Looper.getMainLooper();
        Intrinsics.c(mainLooper, "Looper.getMainLooper()");
        if (mainLooper.getThread() != Thread.currentThread()) {
            throw new IllegalStateException(("Should be called from the main thread, not " + Thread.currentThread()).toString());
        }
        for (w wVar : enumSetAllOf) {
            if (!wVar.a) {
                wVar.a(application);
                wVar.a = true;
            }
        }
        return true;
    }

    @Override // android.content.ContentProvider
    public final Cursor query(Uri uri, String[] strArr, String str, String[] strArr2, String str2) {
        Intrinsics.f(uri, "uri");
        return null;
    }

    @Override // android.content.ContentProvider
    public final int update(Uri uri, ContentValues contentValues, String str, String[] strArr) {
        Intrinsics.f(uri, "uri");
        return 0;
    }
}
