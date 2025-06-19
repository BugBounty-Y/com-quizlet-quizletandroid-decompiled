package com.braze.triggers.managers;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.braze.AbstractC1475a;
import com.braze.AbstractC1484j;
import com.braze.support.BrazeFileUtils;
import com.braze.support.BrazeLogger;
import com.braze.support.WebContentUtils;
import com.braze.support.w;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class b {
    public static final a e = new a();
    public final SharedPreferences a;
    public final ConcurrentHashMap b;
    public final LinkedHashMap c;
    public final File d;

    public b(Context context, String apiKey) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.appboy.storage.triggers.local_assets." + apiKey, 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        this.a = sharedPreferences;
        this.b = e.a(sharedPreferences);
        this.c = new LinkedHashMap();
        this.d = new File(context.getCacheDir().getPath() + "/ab_triggers");
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Could not download ", str);
    }

    public static final String b(String str) {
        return AbstractC1475a.a("Failed to store asset for remote path ", str, ". Not storing local asset");
    }

    public static final String c(String str) {
        return AbstractC1475a.a("Failed to store html zip asset for remote path ", str, ". Not storing local asset");
    }

    public static final String d(String str) {
        return AbstractC1484j.a("Could not find local asset for remote path ", str);
    }

    public static final String e(String str) {
        return AbstractC1484j.a("Failed to add new local path for remote path ", str);
    }

    public static final String b(com.braze.triggers.actions.a aVar) {
        return "Prefetch is turned off for this triggered action. Not retrieving local asset paths. Action id: " + ((com.braze.triggers.actions.g) aVar).a;
    }

    public static final String c(String str, String str2) {
        return AbstractC0147y.e("Adding new local path '", str, "' for remote path '", str2, "' to cache.");
    }

    public final String a(com.braze.triggers.utils.a remotePath) {
        Long lA;
        Intrinsics.checkNotNullParameter(remotePath, "remotePath");
        String str = remotePath.b;
        int iOrdinal = remotePath.a.ordinal();
        if (iOrdinal == 0) {
            String localHtmlUrlFromRemoteUrl = WebContentUtils.getLocalHtmlUrlFromRemoteUrl(this.d, str);
            if (localHtmlUrlFromRemoteUrl == null || StringsKt.O(localHtmlUrlFromRemoteUrl)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new w(str, 13), 7, (Object) null);
                return null;
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new j(0, localHtmlUrlFromRemoteUrl, str), 6, (Object) null);
            return localHtmlUrlFromRemoteUrl;
        }
        if (iOrdinal != 1 && iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        String strB = a.b(str);
        try {
            String string = this.d.toString();
            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
            Pair pairDownloadFileToPath$default = BrazeFileUtils.downloadFileToPath$default(string, str, strB, null, 8, null);
            File file = (File) pairDownloadFileToPath$default.a;
            Map map = (Map) pairDownloadFileToPath$default.b;
            String str2 = (String) map.get("expires");
            if (str2 != null && (lA = com.braze.support.l.a(str2)) != null && lA.longValue() <= 0) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(str, map), 7, (Object) null);
                return null;
            }
            Uri uriFromFile = Uri.fromFile(file);
            if (uriFromFile != null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new k(uriFromFile, str, 0), 6, (Object) null);
                return uriFromFile.getPath();
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new w(str, 16), 7, (Object) null);
            return null;
        } catch (Exception e2) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e2, false, (Function0) new w(str, 17), 4, (Object) null);
            return null;
        }
    }

    public static final String b(String str, String str2) {
        return android.support.v4.media.session.a.m("Found local asset at path ", str, " for remote asset at path: ", str2);
    }

    public static final String c(com.braze.triggers.actions.a aVar) {
        return "No local assets found for action id: " + ((com.braze.triggers.actions.g) aVar).a;
    }

    public final void a(List triggeredActions) {
        Intrinsics.checkNotNullParameter(triggeredActions, "triggeredActions");
        a aVar = e;
        Pair pairA = aVar.a(triggeredActions);
        Set set = (Set) pairA.a;
        Set set2 = (Set) pairA.b;
        SharedPreferences.Editor editorEdit = this.a.edit();
        Intrinsics.d(editorEdit);
        aVar.a(editorEdit, this.b, set2, this.c);
        aVar.a(this.d, this.b, this.c);
        ArrayList arrayList = new ArrayList();
        for (Object obj : set) {
            if (!this.b.containsKey(((com.braze.triggers.utils.a) obj).b)) {
                arrayList.add(obj);
            }
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            com.braze.triggers.utils.a aVar2 = (com.braze.triggers.utils.a) it2.next();
            String str = aVar2.b;
            try {
                String strA = a(aVar2);
                if (strA != null && !StringsKt.O(strA)) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new j(2, strA, str), 7, (Object) null);
                    this.b.put(str, strA);
                    editorEdit.putString(str, strA);
                }
            } catch (Exception e2) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e2, false, (Function0) new w(str, 15), 4, (Object) null);
            }
        }
        editorEdit.apply();
    }

    public final Map a(com.braze.triggers.actions.a triggeredAction) {
        Intrinsics.checkNotNullParameter(triggeredAction, "triggeredAction");
        if (!((com.braze.triggers.actions.g) triggeredAction).c) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.events.g(triggeredAction, 2), 7, (Object) null);
            return V.c();
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Iterator it2 = triggeredAction.a().iterator();
        while (it2.hasNext()) {
            String str = ((com.braze.triggers.utils.a) it2.next()).b;
            String path = (String) this.b.get(str);
            if (path != null) {
                Intrinsics.checkNotNullParameter(path, "path");
                if (new File(path).exists()) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new j(1, path, str), 7, (Object) null);
                    this.c.put(str, path);
                    linkedHashMap.put(str, path);
                }
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new w(str, 14), 6, (Object) null);
        }
        if (linkedHashMap.isEmpty()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.events.g(triggeredAction, 3), 6, (Object) null);
        }
        return linkedHashMap;
    }

    public static final String a(String str, String str2) {
        return android.support.v4.media.session.a.m("Storing local triggered action html zip asset at local path ", str, " for remote path ", str2);
    }

    public static final String a(String str, Map map) {
        return "Not caching " + str + " due to headers " + map;
    }

    public static final String a(Uri uri, String str) {
        return "Storing local triggered action asset at local path " + uri.getPath() + " for remote path " + str;
    }
}
