package com.braze.triggers.managers;

import android.content.SharedPreferences;
import android.net.Uri;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.navigation.C1265a;
import com.braze.AbstractC1475a;
import com.braze.AbstractC1476b;
import com.braze.AbstractC1477c;
import com.braze.C1481g;
import com.braze.requests.framework.o;
import com.braze.storage.C;
import com.braze.support.BrazeFileUtils;
import com.braze.support.BrazeLogger;
import com.braze.support.IntentUtils;
import com.braze.support.w;
import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.Pair;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class a {
    public static final String a(String str) {
        return AbstractC1475a.a("Not removing local path for remote path ", str, " from cache because it is being preserved until the end of the app run.");
    }

    public static final String b(File file) {
        return "Deleting obsolete asset '" + file.getPath() + "' from filesystem.";
    }

    public static final String c(String str) {
        return AbstractC1476b.a("Encountered unexpected exception while parsing stored triggered action local assets on remote asset '", str, '\'');
    }

    public static final String b(String str, String str2) {
        return "Retrieving trigger local asset path '" + str + "' from local storage for remote path '" + str2 + '\'';
    }

    public final void a(File triggeredAssetDirectory, ConcurrentHashMap remoteToLocalAssetsMap, LinkedHashMap preservedLocalAssetMap) {
        Intrinsics.checkNotNullParameter(triggeredAssetDirectory, "triggeredAssetDirectory");
        Intrinsics.checkNotNullParameter(remoteToLocalAssetsMap, "remoteToLocalAssetsMap");
        Intrinsics.checkNotNullParameter(preservedLocalAssetMap, "preservedLocalAssetMap");
        File[] fileArrListFiles = triggeredAssetDirectory.listFiles();
        if (fileArrListFiles == null) {
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new o(fileArrListFiles, 10), 6, (Object) null);
        try {
            ArrayList arrayList = new ArrayList();
            for (File file : fileArrListFiles) {
                if (!remoteToLocalAssetsMap.containsValue(file.getPath())) {
                    arrayList.add(file);
                }
            }
            ArrayList arrayList2 = new ArrayList();
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                Object next = it2.next();
                if (!preservedLocalAssetMap.containsValue(((File) next).getPath())) {
                    arrayList2.add(next);
                }
            }
            Iterator it3 = arrayList2.iterator();
            while (it3.hasNext()) {
                File file2 = (File) it3.next();
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) b.e, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.support.o(file2, 2), 7, (Object) null);
                Intrinsics.d(file2);
                BrazeFileUtils.deleteFileOrDirectory(file2);
            }
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new i(0), 4, (Object) null);
        }
    }

    public static String b(String remoteAssetUrl) {
        String lastPathSegment;
        int iP;
        Intrinsics.checkNotNullParameter(remoteAssetUrl, "remoteAssetUrl");
        J j = new J();
        j.a = "";
        Uri uri = Uri.parse(remoteAssetUrl);
        if (uri != null && (lastPathSegment = uri.getLastPathSegment()) != null && lastPathSegment.length() != 0 && (iP = StringsKt.P(lastPathSegment, '.', 0, 6)) > -1) {
            String strSubstring = lastPathSegment.substring(iP);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
            j.a = strSubstring;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) b.e, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C(j, remoteAssetUrl, 2), 6, (Object) null);
        }
        return IntentUtils.getRequestCode() + ((String) j.a);
    }

    public static final String a(File[] fileArr) {
        return "Local triggered asset directory contains files: " + C4933y.H(fileArr, " , ", new C1265a(26), 30);
    }

    public static final CharSequence a(File file) {
        String name = file.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        return name;
    }

    public static final String a() {
        return "Exception while deleting obsolete assets from filesystem.";
    }

    public final ConcurrentHashMap a(SharedPreferences storagePrefs) {
        Intrinsics.checkNotNullParameter(storagePrefs, "storagePrefs");
        ConcurrentHashMap concurrentHashMap = new ConcurrentHashMap();
        Map<String, ?> all = storagePrefs.getAll();
        if (all != null && !all.isEmpty()) {
            for (String str : all.keySet()) {
                try {
                    String string = storagePrefs.getString(str, null);
                    if (string != null && !StringsKt.O(string)) {
                        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1481g(28, string, str), 7, (Object) null);
                        concurrentHashMap.put(str, string);
                    }
                } catch (Exception e) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new w(str, 11), 4, (Object) null);
                }
            }
        }
        return concurrentHashMap;
    }

    public final void a(SharedPreferences.Editor editor, ConcurrentHashMap localAssetPaths, Set newRemotePathStrings, LinkedHashMap preservedLocalAssetPathMap) {
        Intrinsics.checkNotNullParameter(editor, "editor");
        Intrinsics.checkNotNullParameter(localAssetPaths, "localAssetPaths");
        Intrinsics.checkNotNullParameter(newRemotePathStrings, "newRemotePathStrings");
        Intrinsics.checkNotNullParameter(preservedLocalAssetPathMap, "preservedLocalAssetPathMap");
        Iterator it2 = new HashSet(localAssetPaths.keySet()).iterator();
        Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
        while (it2.hasNext()) {
            String str = (String) it2.next();
            if (preservedLocalAssetPathMap.containsKey(str)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new w(str, 12), 7, (Object) null);
            } else if (!newRemotePathStrings.contains(str)) {
                localAssetPaths.remove(str);
                editor.remove(str);
                String str2 = (String) localAssetPaths.get(str);
                if (str2 != null && !StringsKt.O(str2)) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1481g(29, str2, str), 7, (Object) null);
                    BrazeFileUtils.deleteFileOrDirectory(new File(str2));
                }
            }
        }
    }

    public static final String a(String str, String str2) {
        return AbstractC0147y.e("Removing obsolete local path ", str, " for obsolete remote path ", str2, " from cache.");
    }

    public final Pair a(List triggeredActions) {
        Intrinsics.checkNotNullParameter(triggeredActions, "triggeredActions");
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        LinkedHashSet linkedHashSet2 = new LinkedHashSet();
        Iterator it2 = triggeredActions.iterator();
        while (it2.hasNext()) {
            com.braze.triggers.actions.a aVar = (com.braze.triggers.actions.a) it2.next();
            if (!((com.braze.triggers.actions.g) aVar).c) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.events.g(aVar, 1), 7, (Object) null);
            } else {
                Iterator it3 = aVar.a().iterator();
                while (it3.hasNext()) {
                    com.braze.triggers.utils.a aVar2 = (com.braze.triggers.utils.a) it3.next();
                    String str = aVar2.b;
                    if (!StringsKt.O(str)) {
                        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(0, aVar, str), 7, (Object) null);
                        linkedHashSet.add(aVar2);
                        linkedHashSet2.add(str);
                    }
                }
            }
        }
        return new Pair(linkedHashSet, linkedHashSet2);
    }

    public static final String a(com.braze.triggers.actions.a aVar) {
        return AbstractC1477c.a(new StringBuilder("Pre-fetch off for triggered action "), ((com.braze.triggers.actions.g) aVar).a, ". Not pre-fetching assets.");
    }

    public static final String a(com.braze.triggers.actions.a aVar, String str) {
        return "Received new remote path for triggered action " + ((com.braze.triggers.actions.g) aVar).a + " at " + str + '.';
    }

    public static final String a(J j, String str) {
        return AbstractC0147y.g(new StringBuilder("Using file extension "), (String) j.a, " for remote asset url: ", str);
    }
}
