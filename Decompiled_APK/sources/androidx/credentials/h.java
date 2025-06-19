package androidx.credentials;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class h {
    public final Context a;

    public h(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    public static g a(h hVar, Object request) {
        Intrinsics.checkNotNullParameter(request, "request");
        if (Intrinsics.b(request, "androidx.credentials.TYPE_CLEAR_RESTORE_CREDENTIAL")) {
            return hVar.b();
        }
        if (request instanceof o) {
            for (q qVar : ((o) request).a) {
            }
        }
        int i = Build.VERSION.SDK_INT;
        if (i >= 34) {
            l lVar = new l(hVar.a);
            l lVar2 = lVar.isAvailableOnDevice() ? lVar : null;
            return lVar2 == null ? hVar.b() : lVar2;
        }
        if (i <= 33) {
            return hVar.b();
        }
        return null;
    }

    public final g b() throws PackageManager.NameNotFoundException {
        String string;
        Context context = this.a;
        PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 132);
        ArrayList arrayList = new ArrayList();
        ServiceInfo[] serviceInfoArr = packageInfo.services;
        if (serviceInfoArr != null) {
            for (ServiceInfo serviceInfo : serviceInfoArr) {
                Bundle bundle = serviceInfo.metaData;
                if (bundle != null && (string = bundle.getString("androidx.credentials.CREDENTIAL_PROVIDER_KEY")) != null) {
                    arrayList.add(string);
                }
            }
        }
        List listW0 = CollectionsKt.w0(arrayList);
        if (listW0.isEmpty()) {
            return null;
        }
        Iterator it2 = listW0.iterator();
        g gVar = null;
        while (it2.hasNext()) {
            try {
                Object objNewInstance = Class.forName((String) it2.next()).getConstructor(Context.class).newInstance(context);
                Intrinsics.e(objNewInstance, "null cannot be cast to non-null type androidx.credentials.CredentialProvider");
                g gVar2 = (g) objNewInstance;
                if (!gVar2.isAvailableOnDevice()) {
                    continue;
                } else {
                    if (gVar != null) {
                        Log.i("CredProviderFactory", "Only one active OEM CredentialProvider allowed");
                        return null;
                    }
                    gVar = gVar2;
                }
            } catch (Throwable unused) {
            }
        }
        return gVar;
    }
}
