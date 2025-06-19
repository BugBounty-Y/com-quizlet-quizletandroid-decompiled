package com.appsflyer.internal;

import android.content.Context;
import android.util.Base64;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.appsflyer.AFLogger;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.G;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFc1tSDK implements AFc1vSDK {

    @NotNull
    private final AFc1iSDK AFAdRevenueData;

    @NotNull
    private final AFc1qSDK getCurrencyIso4217Code;

    @NotNull
    private final AFc1sSDK getMediationNetwork;

    @NotNull
    private final Map<String, Integer> getRevenue;

    public AFc1tSDK(@NotNull AFc1iSDK aFc1iSDK, @NotNull AFc1qSDK aFc1qSDK) {
        Intrinsics.checkNotNullParameter(aFc1iSDK, "");
        Intrinsics.checkNotNullParameter(aFc1qSDK, "");
        this.AFAdRevenueData = aFc1iSDK;
        this.getCurrencyIso4217Code = aFc1qSDK;
        this.getMediationNetwork = new AFc1sSDK(B.j(new AFc1uSDK("ConversionsCache", A.b(AFe1mSDK.CONVERSION), 1), new AFc1uSDK("AttrCache", A.b(AFe1mSDK.ATTR), 1), new AFc1uSDK("OtherCache", B.j(AFe1mSDK.LAUNCH, AFe1mSDK.INAPP, AFe1mSDK.ADREVENUE, AFe1mSDK.ARS_VALIDATE, AFe1mSDK.PURCHASE_VALIDATE, AFe1mSDK.MANUAL_PURCHASE_VALIDATION, AFe1mSDK.SDK_SERVICES), 40)));
        this.getRevenue = V.g(new Pair("ConversionsCache", 0), new Pair("AttrCache", 0), new Pair("OtherCache", 0));
    }

    private final boolean getCurrencyIso4217Code(File file) {
        try {
            file.delete();
            getMonetizationNetwork();
            return true;
        } catch (Exception e) {
            AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.CACHE, android.support.v4.media.session.a.B("Could not delete ", file.getName(), " from cache"), e, false, false, false, false, 120, null);
            return false;
        }
    }

    private static AFc1rSDK getMediationNetwork(File file) throws IOException {
        try {
            InputStreamReader inputStreamReader = new InputStreamReader(new FileInputStream(file), Charset.defaultCharset());
            try {
                char[] cArr = new char[(int) file.length()];
                inputStreamReader.read(cArr);
                AFc1rSDK aFc1rSDK = new AFc1rSDK(cArr);
                aFc1rSDK.getMediationNetwork = file.getName();
                inputStreamReader.close();
                return aFc1rSDK;
            } finally {
            }
        } catch (Exception e) {
            AFLogger.INSTANCE.e(AFg1cSDK.CACHE, "Error while loading request from cache", e, false, false, true, false);
            return null;
        }
    }

    private final void getMonetizationNetwork() {
        for (AFc1uSDK aFc1uSDK : this.getMediationNetwork.AFAdRevenueData) {
            String str = aFc1uSDK.getCurrencyIso4217Code;
            Context context = this.AFAdRevenueData.getMonetizationNetwork;
            Intrinsics.d(context);
            File file = new File(new File(context.getFilesDir(), "AFRequestCache"), str);
            if (file.exists()) {
                Map<String, Integer> map = this.getRevenue;
                String str2 = aFc1uSDK.getCurrencyIso4217Code;
                File[] fileArrListFiles = file.listFiles();
                map.put(str2, Integer.valueOf(fileArrListFiles != null ? fileArrListFiles.length : 0));
            } else {
                file.mkdirs();
                this.getRevenue.put(aFc1uSDK.getCurrencyIso4217Code, 0);
            }
        }
    }

    @Override // com.appsflyer.internal.AFc1vSDK
    public final void AFAdRevenueData() {
        try {
            if (this.getCurrencyIso4217Code.AFAdRevenueData("AF_CACHE_VERSION", -1) == 1) {
                Context context = this.AFAdRevenueData.getMonetizationNetwork;
                Intrinsics.d(context);
                if (!new File(context.getFilesDir(), "AFRequestCache").exists()) {
                    Context context2 = this.AFAdRevenueData.getMonetizationNetwork;
                    Intrinsics.d(context2);
                    new File(context2.getFilesDir(), "AFRequestCache").mkdir();
                }
            } else {
                this.getCurrencyIso4217Code.getMediationNetwork("AF_CACHE_VERSION", 1);
                Context context3 = this.AFAdRevenueData.getMonetizationNetwork;
                Intrinsics.d(context3);
                if (new File(context3.getFilesDir(), "AFRequestCache").exists()) {
                    Context context4 = this.AFAdRevenueData.getMonetizationNetwork;
                    Intrinsics.d(context4);
                    kotlin.io.k.e(new File(context4.getFilesDir(), "AFRequestCache"));
                    Context context5 = this.AFAdRevenueData.getMonetizationNetwork;
                    Intrinsics.d(context5);
                    new File(context5.getFilesDir(), "AFRequestCache").mkdir();
                }
            }
            getMonetizationNetwork();
        } catch (Exception e) {
            AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.CACHE, "Could not init cache", e, false, false, false, false, 120, null);
        }
    }

    @Override // com.appsflyer.internal.AFc1vSDK
    @NotNull
    public final List<AFc1rSDK> getRevenue() {
        AFg1gSDK.i$default(AFLogger.INSTANCE, AFg1cSDK.CACHE, "Get Cached Requests", false, 4, null);
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        try {
            Context context = this.AFAdRevenueData.getMonetizationNetwork;
            Intrinsics.d(context);
            if (!new File(context.getFilesDir(), "AFRequestCache").exists()) {
                Context context2 = this.AFAdRevenueData.getMonetizationNetwork;
                Intrinsics.d(context2);
                new File(context2.getFilesDir(), "AFRequestCache").mkdir();
            }
            Iterator<T> it2 = this.getMediationNetwork.AFAdRevenueData.iterator();
            while (it2.hasNext()) {
                String str = ((AFc1uSDK) it2.next()).getCurrencyIso4217Code;
                Context context3 = this.AFAdRevenueData.getMonetizationNetwork;
                Intrinsics.d(context3);
                File file = new File(new File(context3.getFilesDir(), "AFRequestCache"), str);
                if (!file.exists()) {
                    file.mkdirs();
                }
                File[] fileArrListFiles = file.listFiles();
                if (fileArrListFiles == null) {
                    fileArrListFiles = new File[0];
                }
                G.v(arrayList2, fileArrListFiles);
            }
            Iterator it3 = arrayList2.iterator();
            while (it3.hasNext()) {
                File file2 = (File) it3.next();
                AFg1gSDK.i$default(AFLogger.INSTANCE, AFg1cSDK.CACHE, "Found cached request: " + file2.getName(), false, 4, null);
                AFc1rSDK mediationNetwork = getMediationNetwork(file2);
                if (mediationNetwork != null) {
                    arrayList.add(mediationNetwork);
                }
            }
        } catch (Exception e) {
            AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.CACHE, "Could not get cached requests", e, false, false, false, false, 120, null);
        }
        AFg1gSDK.i$default(AFLogger.INSTANCE, AFg1cSDK.CACHE, AbstractC0147y.c(arrayList.size(), "Found ", " Cached Requests"), false, 4, null);
        return arrayList;
    }

    private final AFc1uSDK getCurrencyIso4217Code(AFe1mSDK aFe1mSDK) {
        Object next;
        Iterator<T> it2 = this.getMediationNetwork.AFAdRevenueData.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (((AFc1uSDK) next).getRevenue.contains(aFe1mSDK)) {
                break;
            }
        }
        return (AFc1uSDK) next;
    }

    @Override // com.appsflyer.internal.AFc1vSDK
    public final void getMediationNetwork() {
        try {
            Context context = this.AFAdRevenueData.getMonetizationNetwork;
            Intrinsics.d(context);
            if (!new File(context.getFilesDir(), "AFRequestCache").exists()) {
                Context context2 = this.AFAdRevenueData.getMonetizationNetwork;
                Intrinsics.d(context2);
                new File(context2.getFilesDir(), "AFRequestCache").mkdir();
                return;
            }
            Iterator<T> it2 = this.getMediationNetwork.AFAdRevenueData.iterator();
            while (it2.hasNext()) {
                String str = ((AFc1uSDK) it2.next()).getCurrencyIso4217Code;
                Context context3 = this.AFAdRevenueData.getMonetizationNetwork;
                Intrinsics.d(context3);
                File[] fileArrListFiles = new File(new File(context3.getFilesDir(), "AFRequestCache"), str).listFiles();
                if (fileArrListFiles != null) {
                    Intrinsics.checkNotNullExpressionValue(fileArrListFiles, "");
                    for (File file : fileArrListFiles) {
                        AFLogger aFLogger = AFLogger.INSTANCE;
                        AFg1cSDK aFg1cSDK = AFg1cSDK.CACHE;
                        AFg1gSDK.i$default(aFLogger, aFg1cSDK, "ClearCache : Found cached request " + file.getName(), false, 4, null);
                        AFg1gSDK.i$default(aFLogger, aFg1cSDK, "Deleting " + file.getName() + " from cache", false, 4, null);
                        file.delete();
                    }
                }
            }
            Context context4 = this.AFAdRevenueData.getMonetizationNetwork;
            Intrinsics.d(context4);
            kotlin.io.k.e(new File(context4.getFilesDir(), "AFRequestCache"));
            getMonetizationNetwork();
        } catch (Exception e) {
            AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.CACHE, "Could not clearCache request", e, false, false, false, false, 120, null);
        }
    }

    @Override // com.appsflyer.internal.AFc1vSDK
    public final String AFAdRevenueData(@NotNull AFc1rSDK aFc1rSDK) throws IOException {
        Exception exc;
        File file;
        AFLogger aFLogger;
        AFg1cSDK aFg1cSDK;
        String strValueOf;
        String str;
        List listK;
        List<File> listP0;
        Intrinsics.checkNotNullParameter(aFc1rSDK, "");
        try {
            AFe1mSDK aFe1mSDK = aFc1rSDK.getMonetizationNetwork;
            Intrinsics.checkNotNullExpressionValue(aFe1mSDK, "");
            Context context = this.AFAdRevenueData.getMonetizationNetwork;
            Intrinsics.d(context);
            File file2 = new File(new File(context.getFilesDir(), "AFRequestCache"), getMediationNetwork(aFe1mSDK));
            if (!file2.exists()) {
                file2.mkdirs();
            }
            aFLogger = AFLogger.INSTANCE;
            aFg1cSDK = AFg1cSDK.CACHE;
            AFg1gSDK.i$default(aFLogger, aFg1cSDK, "Caching request with URL: " + aFc1rSDK.getRevenue, false, 4, null);
            strValueOf = String.valueOf(System.currentTimeMillis());
            file = new File(file2, strValueOf);
        } catch (Exception e) {
            exc = e;
            file = null;
        }
        try {
            file.createNewFile();
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(new FileOutputStream(file.getPath(), true), Charset.defaultCharset());
            try {
                outputStreamWriter.write("version=");
                outputStreamWriter.write(aFc1rSDK.AFAdRevenueData);
                outputStreamWriter.write(10);
                outputStreamWriter.write("url=");
                outputStreamWriter.write(aFc1rSDK.getRevenue);
                outputStreamWriter.write(10);
                outputStreamWriter.write("data=");
                outputStreamWriter.write(Base64.encodeToString(aFc1rSDK.getMediationNetwork(), 2));
                outputStreamWriter.write(10);
                AFe1mSDK aFe1mSDK2 = aFc1rSDK.getMonetizationNetwork;
                outputStreamWriter.write("type=");
                outputStreamWriter.write(aFe1mSDK2.name());
                outputStreamWriter.write(10);
                outputStreamWriter.flush();
                Unit unit = Unit.a;
                outputStreamWriter.close();
                AFg1gSDK.i$default(aFLogger, aFg1cSDK, "Cache request: done, cacheKey: " + strValueOf, false, 4, null);
                AFe1mSDK aFe1mSDK3 = aFc1rSDK.getMonetizationNetwork;
                Intrinsics.checkNotNullExpressionValue(aFe1mSDK3, "");
                AFc1uSDK currencyIso4217Code = getCurrencyIso4217Code(aFe1mSDK3);
                Integer numValueOf = currencyIso4217Code != null ? Integer.valueOf(currencyIso4217Code.AFAdRevenueData) : null;
                if (numValueOf == null) {
                    return strValueOf;
                }
                int iIntValue = numValueOf.intValue();
                Map<String, Integer> map = this.getRevenue;
                AFc1uSDK currencyIso4217Code2 = getCurrencyIso4217Code(aFe1mSDK3);
                if (currencyIso4217Code2 != null && (str = currencyIso4217Code2.getCurrencyIso4217Code) != null) {
                    Integer num = map.get(str);
                    int iIntValue2 = num != null ? num.intValue() : 0;
                    if (iIntValue2 >= iIntValue) {
                        int i = (iIntValue2 + 1) - iIntValue;
                        AFg1gSDK.i$default(aFLogger, aFg1cSDK, "Cache overflown for type " + aFe1mSDK3 + ", removing " + i + " item(s)", false, 4, null);
                        Context context2 = this.AFAdRevenueData.getMonetizationNetwork;
                        Intrinsics.d(context2);
                        File file3 = new File(new File(context2.getFilesDir(), "AFRequestCache"), getMediationNetwork(aFe1mSDK3));
                        if (!file3.exists()) {
                            file3.mkdirs();
                        }
                        File[] fileArrListFiles = file3.listFiles();
                        if (fileArrListFiles != null && (listK = C4933y.K(fileArrListFiles, new Comparator() { // from class: com.appsflyer.internal.AFc1tSDK.1
                            /* JADX WARN: Multi-variable type inference failed */
                            @Override // java.util.Comparator
                            public final int compare(T t, T t2) {
                                return kotlin.comparisons.a.b(((File) t).getName(), ((File) t2).getName());
                            }
                        })) != null && (listP0 = CollectionsKt.p0(listK, i)) != null) {
                            for (File file4 : listP0) {
                                file4.delete();
                                AFg1gSDK.i$default(AFLogger.INSTANCE, AFg1cSDK.CACHE, "Cache entry " + file4.getName() + " removed", false, 4, null);
                            }
                        }
                    }
                    getMonetizationNetwork();
                    return strValueOf;
                }
                throw new UnsupportedOperationException("Cache do not support this type of events");
            } finally {
            }
        } catch (Exception e2) {
            exc = e2;
            if (file != null) {
                file.delete();
            }
            AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.CACHE, "Could not cache request", exc, false, false, false, false, 120, null);
            return null;
        }
    }

    private final String getMediationNetwork(AFe1mSDK aFe1mSDK) {
        String str;
        AFc1uSDK currencyIso4217Code = getCurrencyIso4217Code(aFe1mSDK);
        if (currencyIso4217Code == null || (str = currencyIso4217Code.getCurrencyIso4217Code) == null) {
            throw new UnsupportedOperationException("Cache do not support this type of events");
        }
        return str;
    }

    @Override // com.appsflyer.internal.AFc1vSDK
    public final boolean AFAdRevenueData(String str) {
        if (str == null) {
            return false;
        }
        Context context = this.AFAdRevenueData.getMonetizationNetwork;
        Intrinsics.d(context);
        if (!new File(context.getFilesDir(), "AFRequestCache").exists()) {
            Context context2 = this.AFAdRevenueData.getMonetizationNetwork;
            Intrinsics.d(context2);
            new File(context2.getFilesDir(), "AFRequestCache").mkdir();
            return true;
        }
        AFg1gSDK.i$default(AFLogger.INSTANCE, AFg1cSDK.CACHE, android.support.v4.media.session.a.B("Deleting ", str, " from cache"), false, 4, null);
        Iterator<T> it2 = this.getMediationNetwork.AFAdRevenueData.iterator();
        while (it2.hasNext()) {
            String str2 = ((AFc1uSDK) it2.next()).getCurrencyIso4217Code;
            Context context3 = this.AFAdRevenueData.getMonetizationNetwork;
            Intrinsics.d(context3);
            File file = new File(new File(new File(context3.getFilesDir(), "AFRequestCache"), str2), str);
            if (file.exists()) {
                return getCurrencyIso4217Code(file);
            }
        }
        return true;
    }
}
